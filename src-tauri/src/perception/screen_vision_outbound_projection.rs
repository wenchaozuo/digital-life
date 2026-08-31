//! Pure local D25-C1 projection of a validated D23 BGRA8 frame.
//!
//! The projection accepts only an explicit source-space crop and bounded
//! source-space privacy masks.  It produces a metadata-free RGB8 buffer that
//! remains process-local and is zeroized when dropped.  This module does not
//! perform consent, session, capture-target, candidate, grant, attachment,
//! provider, IPC, or network authorization.
//!
//! A successful local projection DOES NOT authorize network transmission.

use super::screen_capture::ScreenFrame;
use zeroize::Zeroizing;

pub(crate) const MAX_OUTBOUND_IMAGE_EDGE: u32 = 1_600;
pub(crate) const MAX_OUTBOUND_IMAGE_PIXELS: u64 = 2_560_000;
pub(crate) const MAX_OUTBOUND_RGB_BYTES: u64 = 7_680_000;
pub(crate) const MAX_PRIVACY_MASK_RECTS: usize = 64;

const SOURCE_BYTES_PER_PIXEL: u64 = 4;
const RGB_BYTES_PER_PIXEL: u64 = 3;

/// A source-space half-open rectangle.  A projection request must carry one
/// explicitly; there is intentionally no whole-frame default.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundRect {
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl ScreenVisionOutboundRect {
    pub(crate) const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// The explicit crop and bounded source-space privacy mask plan for one
/// projection.  The crop is not optional and is never inferred from a frame.
pub(crate) struct ScreenVisionOutboundProjectionRequest {
    pub(crate) crop: ScreenVisionOutboundRect,
    pub(crate) mask_rects: Vec<ScreenVisionOutboundRect>,
}

impl ScreenVisionOutboundProjectionRequest {
    pub(crate) fn new(
        crop: ScreenVisionOutboundRect,
        mask_rects: Vec<ScreenVisionOutboundRect>,
    ) -> Self {
        Self { crop, mask_rects }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundPixelFormat {
    Rgb8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundProjectionErrorCode {
    FrameInvalid,
    CropInvalid,
    MaskInvalid,
    TooManyMasks,
    ProjectionOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundProjectionError {
    code: ScreenVisionOutboundProjectionErrorCode,
}

impl ScreenVisionOutboundProjectionError {
    const fn new(code: ScreenVisionOutboundProjectionErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ScreenVisionOutboundProjectionErrorCode {
        self.code
    }
}

/// Metadata-free RGB8 output whose sensitive bytes are owned by a zeroizing
/// buffer.  The bytes are intentionally private; callers can borrow them only
/// through `as_bytes`, and there is no persistence or serialization method.
#[must_use]
pub(crate) struct ScreenVisionOutboundProjection {
    width: u32,
    height: u32,
    pixel_format: ScreenVisionOutboundPixelFormat,
    bytes: Zeroizing<Vec<u8>>,
}

impl ScreenVisionOutboundProjection {
    pub(crate) const fn width(&self) -> u32 {
        self.width
    }

    pub(crate) const fn height(&self) -> u32 {
        self.height
    }

    pub(crate) const fn pixel_format(&self) -> ScreenVisionOutboundPixelFormat {
        self.pixel_format
    }

    /// Borrows RGB8 bytes for a later, separately authorized consumer.  This
    /// method does not authorize or perform any outbound transmission.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Clone, Copy)]
struct ValidatedRect {
    x: u32,
    y: u32,
    right: u32,
    bottom: u32,
    width: u32,
    height: u32,
}

impl ValidatedRect {
    const EMPTY: Self = Self {
        x: 0,
        y: 0,
        right: 0,
        bottom: 0,
        width: 0,
        height: 0,
    };
}

/// Validate the frame, explicit crop, and bounded masks, then transform each
/// output pixel directly from one nearest-neighbor source pixel.  No raw,
/// cropped, or masked pixel copy is retained.
pub(crate) fn project_screen_frame(
    frame: &ScreenFrame,
    request: &ScreenVisionOutboundProjectionRequest,
) -> Result<ScreenVisionOutboundProjection, ScreenVisionOutboundProjectionError> {
    // This is deliberately the first operation that could permit pixel reads.
    // D23 remains the authority for the raw frame's geometry and byte length.
    frame
        .validate()
        .map_err(|_| projection_error(ScreenVisionOutboundProjectionErrorCode::FrameInvalid))?;

    let crop = validate_crop(request.crop, frame)?;

    if request.mask_rects.len() > MAX_PRIVACY_MASK_RECTS {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::TooManyMasks,
        ));
    }

    // Keep only bounded, checked geometry on the stack.  No pixel buffer is
    // copied or duplicated while the mask plan is validated.
    let mut masks = [ValidatedRect::EMPTY; MAX_PRIVACY_MASK_RECTS];
    for (index, mask) in request.mask_rects.iter().enumerate() {
        masks[index] = validate_mask(*mask, frame)?;
    }

    let (output_width, output_height) = output_dimensions(crop)?;
    let output_len = output_byte_len(output_width, output_height)?;
    let mut bytes = Zeroizing::new(vec![0_u8; output_len]);

    for output_y in 0..output_height {
        let source_y = crop
            .y
            .checked_add(nearest_source_coordinate(
                output_y,
                crop.height,
                output_height,
            )?)
            .ok_or_else(|| {
                projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
            })?;

        for output_x in 0..output_width {
            let source_x = crop
                .x
                .checked_add(nearest_source_coordinate(
                    output_x,
                    crop.width,
                    output_width,
                )?)
                .ok_or_else(|| {
                    projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
                })?;

            let output_offset =
                pixel_byte_offset(output_x, output_y, output_width, RGB_BYTES_PER_PIXEL)?;
            let output_end = output_offset
                .checked_add(usize::try_from(RGB_BYTES_PER_PIXEL).map_err(|_| {
                    projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
                })?)
                .ok_or_else(|| {
                    projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
                })?;
            let output_pixel = bytes.get_mut(output_offset..output_end).ok_or_else(|| {
                projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
            })?;

            if masks[..request.mask_rects.len()]
                .iter()
                .any(|mask| source_pixel_is_masked(source_x, source_y, *mask))
            {
                output_pixel.fill(0);
                continue;
            }

            let source_offset = source_byte_offset(frame, source_x, source_y)?;
            let source_end = source_offset
                .checked_add(usize::try_from(SOURCE_BYTES_PER_PIXEL).map_err(|_| {
                    projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
                })?)
                .ok_or_else(|| {
                    projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
                })?;
            let source_pixel = frame.bytes.get(source_offset..source_end).ok_or_else(|| {
                projection_error(ScreenVisionOutboundProjectionErrorCode::FrameInvalid)
            })?;

            // ScreenFrame is validated BGRA8.  Alpha and the BGRA padding
            // byte are intentionally discarded; output order is R,G,B.
            output_pixel[0] = source_pixel[2];
            output_pixel[1] = source_pixel[1];
            output_pixel[2] = source_pixel[0];
        }
    }

    Ok(ScreenVisionOutboundProjection {
        width: output_width,
        height: output_height,
        pixel_format: ScreenVisionOutboundPixelFormat::Rgb8,
        bytes,
    })
}

fn projection_error(
    code: ScreenVisionOutboundProjectionErrorCode,
) -> ScreenVisionOutboundProjectionError {
    ScreenVisionOutboundProjectionError::new(code)
}

fn validate_crop(
    rect: ScreenVisionOutboundRect,
    frame: &ScreenFrame,
) -> Result<ValidatedRect, ScreenVisionOutboundProjectionError> {
    if rect.width == 0 || rect.height == 0 {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::CropInvalid,
        ));
    }

    let right = rect.x.checked_add(rect.width).ok_or_else(|| {
        projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
    })?;
    let bottom = rect.y.checked_add(rect.height).ok_or_else(|| {
        projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
    })?;
    if right > frame.width || bottom > frame.height {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::CropInvalid,
        ));
    }

    Ok(ValidatedRect {
        x: rect.x,
        y: rect.y,
        right,
        bottom,
        width: rect.width,
        height: rect.height,
    })
}

fn validate_mask(
    rect: ScreenVisionOutboundRect,
    frame: &ScreenFrame,
) -> Result<ValidatedRect, ScreenVisionOutboundProjectionError> {
    if rect.width == 0 || rect.height == 0 {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::MaskInvalid,
        ));
    }

    let right = rect.x.checked_add(rect.width).ok_or_else(|| {
        projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
    })?;
    let bottom = rect.y.checked_add(rect.height).ok_or_else(|| {
        projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
    })?;
    if right > frame.width || bottom > frame.height {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::MaskInvalid,
        ));
    }

    Ok(ValidatedRect {
        x: rect.x,
        y: rect.y,
        right,
        bottom,
        width: rect.width,
        height: rect.height,
    })
}

fn output_dimensions(
    crop: ValidatedRect,
) -> Result<(u32, u32), ScreenVisionOutboundProjectionError> {
    let source_long_edge = crop.width.max(crop.height);
    let (width, height) = if source_long_edge <= MAX_OUTBOUND_IMAGE_EDGE {
        (crop.width, crop.height)
    } else {
        (
            scaled_dimension(crop.width, MAX_OUTBOUND_IMAGE_EDGE, source_long_edge)?,
            scaled_dimension(crop.height, MAX_OUTBOUND_IMAGE_EDGE, source_long_edge)?,
        )
    };

    if width == 0
        || height == 0
        || width > crop.width
        || height > crop.height
        || width > MAX_OUTBOUND_IMAGE_EDGE
        || height > MAX_OUTBOUND_IMAGE_EDGE
    {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow,
        ));
    }

    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    if pixels > MAX_OUTBOUND_IMAGE_PIXELS {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow,
        ));
    }

    Ok((width, height))
}

fn scaled_dimension(
    source_dimension: u32,
    target_long_edge: u32,
    source_long_edge: u32,
) -> Result<u32, ScreenVisionOutboundProjectionError> {
    let numerator = u64::from(source_dimension)
        .checked_mul(u64::from(target_long_edge))
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    let scaled = numerator / u64::from(source_long_edge);
    let scaled = scaled.max(1);
    u32::try_from(scaled)
        .map_err(|_| projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow))
}

fn output_byte_len(width: u32, height: u32) -> Result<usize, ScreenVisionOutboundProjectionError> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    if pixels > MAX_OUTBOUND_IMAGE_PIXELS {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow,
        ));
    }

    let bytes = pixels.checked_mul(RGB_BYTES_PER_PIXEL).ok_or_else(|| {
        projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
    })?;
    if bytes > MAX_OUTBOUND_RGB_BYTES {
        return Err(projection_error(
            ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow,
        ));
    }

    usize::try_from(bytes)
        .map_err(|_| projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow))
}

fn nearest_source_coordinate(
    destination_coordinate: u32,
    source_extent: u32,
    destination_extent: u32,
) -> Result<u32, ScreenVisionOutboundProjectionError> {
    let twice_destination = u64::from(destination_coordinate)
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    let numerator = twice_destination
        .checked_mul(u64::from(source_extent))
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    let denominator = u64::from(destination_extent)
        .checked_mul(2)
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    let source_coordinate = numerator / denominator;
    u32::try_from(source_coordinate)
        .map_err(|_| projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow))
}

fn pixel_byte_offset(
    x: u32,
    y: u32,
    width: u32,
    bytes_per_pixel: u64,
) -> Result<usize, ScreenVisionOutboundProjectionError> {
    let pixel_index = u64::from(y)
        .checked_mul(u64::from(width))
        .and_then(|row| row.checked_add(u64::from(x)))
        .ok_or_else(|| {
            projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
        })?;
    let byte_offset = pixel_index.checked_mul(bytes_per_pixel).ok_or_else(|| {
        projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow)
    })?;
    usize::try_from(byte_offset)
        .map_err(|_| projection_error(ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow))
}

fn source_byte_offset(
    frame: &ScreenFrame,
    x: u32,
    y: u32,
) -> Result<usize, ScreenVisionOutboundProjectionError> {
    // Keep the source calculation visibly equivalent to
    // ((y * frame_width) + x) * 4, with checked u64 arithmetic throughout.
    pixel_byte_offset(x, y, frame.width, SOURCE_BYTES_PER_PIXEL)
}

fn source_pixel_is_masked(x: u32, y: u32, mask: ValidatedRect) -> bool {
    mask.x <= x && x < mask.right && mask.y <= y && y < mask.bottom
}

#[cfg(test)]
mod tests {
    use super::super::screen_capture::ScreenPixelFormat;
    use super::*;

    fn frame_with_pixels<F>(width: u32, height: u32, mut pixel: F) -> ScreenFrame
    where
        F: FnMut(u32, u32) -> [u8; 4],
    {
        let pixel_count = u64::from(width)
            .checked_mul(u64::from(height))
            .expect("test geometry must fit");
        let byte_len = pixel_count
            .checked_mul(SOURCE_BYTES_PER_PIXEL)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .expect("test geometry must fit");
        let mut bytes = Vec::with_capacity(byte_len);
        for y in 0..height {
            for x in 0..width {
                let [b, g, r, a] = pixel(x, y);
                bytes.extend_from_slice(&[b, g, r, a]);
            }
        }
        ScreenFrame {
            width,
            height,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes,
        }
    }

    fn solid_frame(width: u32, height: u32, bgra: [u8; 4]) -> ScreenFrame {
        frame_with_pixels(width, height, |_x, _y| bgra)
    }

    fn rect(x: u32, y: u32, width: u32, height: u32) -> ScreenVisionOutboundRect {
        ScreenVisionOutboundRect::new(x, y, width, height)
    }

    fn small_test_byte(value: u32) -> u8 {
        u8::try_from(value).expect("test coordinate must fit in one byte")
    }

    fn request(
        crop: ScreenVisionOutboundRect,
        mask_rects: Vec<ScreenVisionOutboundRect>,
    ) -> ScreenVisionOutboundProjectionRequest {
        ScreenVisionOutboundProjectionRequest::new(crop, mask_rects)
    }

    fn project(
        frame: &ScreenFrame,
        crop: ScreenVisionOutboundRect,
        mask_rects: Vec<ScreenVisionOutboundRect>,
    ) -> ScreenVisionOutboundProjection {
        project_screen_frame(frame, &request(crop, mask_rects)).expect("projection should succeed")
    }

    fn error_code(
        frame: &ScreenFrame,
        crop: ScreenVisionOutboundRect,
        mask_rects: Vec<ScreenVisionOutboundRect>,
    ) -> ScreenVisionOutboundProjectionErrorCode {
        match project_screen_frame(frame, &request(crop, mask_rects)) {
            Ok(_) => panic!("projection should reject"),
            Err(error) => error.code(),
        }
    }

    #[test]
    fn one_by_one_bgra_converts_exactly_to_rgb() {
        let frame = solid_frame(1, 1, [3, 2, 1, 255]);
        let projection = project(&frame, rect(0, 0, 1, 1), vec![]);

        assert_eq!(
            projection.pixel_format(),
            ScreenVisionOutboundPixelFormat::Rgb8
        );
        assert_eq!(projection.width(), 1);
        assert_eq!(projection.height(), 1);
        assert_eq!(projection.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn alpha_is_discarded_from_rgb8_output() {
        let opaque = solid_frame(1, 1, [30, 20, 10, 255]);
        let transparent = solid_frame(1, 1, [30, 20, 10, 0]);

        assert_eq!(
            project(&opaque, rect(0, 0, 1, 1), vec![]).as_bytes(),
            &[10, 20, 30]
        );
        assert_eq!(
            project(&transparent, rect(0, 0, 1, 1), vec![]).as_bytes(),
            &[10, 20, 30]
        );
    }

    #[test]
    fn crop_extracts_only_the_selected_source_region() {
        let frame = frame_with_pixels(3, 2, |x, y| {
            [small_test_byte(x), small_test_byte(y), 10, 255]
        });
        let projection = project(&frame, rect(1, 0, 2, 1), vec![]);

        assert_eq!(projection.width(), 2);
        assert_eq!(projection.height(), 1);
        assert_eq!(projection.as_bytes(), &[10, 0, 1, 10, 0, 2]);
    }

    #[test]
    fn zero_crop_width_rejects() {
        let frame = solid_frame(2, 2, [0, 0, 0, 255]);
        assert_eq!(
            error_code(&frame, rect(0, 0, 0, 2), vec![]),
            ScreenVisionOutboundProjectionErrorCode::CropInvalid
        );
    }

    #[test]
    fn zero_crop_height_rejects() {
        let frame = solid_frame(2, 2, [0, 0, 0, 255]);
        assert_eq!(
            error_code(&frame, rect(0, 0, 2, 0), vec![]),
            ScreenVisionOutboundProjectionErrorCode::CropInvalid
        );
    }

    #[test]
    fn out_of_bounds_crop_rejects() {
        let frame = solid_frame(2, 2, [0, 0, 0, 255]);
        assert_eq!(
            error_code(&frame, rect(1, 1, 2, 1), vec![]),
            ScreenVisionOutboundProjectionErrorCode::CropInvalid
        );
    }

    #[test]
    fn checked_overflow_geometry_rejects() {
        let frame = solid_frame(2, 2, [0, 0, 0, 255]);
        assert_eq!(
            error_code(&frame, rect(u32::MAX, 0, 1, 1), vec![]),
            ScreenVisionOutboundProjectionErrorCode::ProjectionOverflow
        );
    }

    #[test]
    fn invalid_screen_frame_rejects_before_projection() {
        let frame = ScreenFrame {
            width: 1,
            height: 1,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![1, 2, 3],
        };

        assert_eq!(
            error_code(&frame, rect(0, 0, 1, 1), vec![]),
            ScreenVisionOutboundProjectionErrorCode::FrameInvalid
        );
    }

    #[test]
    fn one_privacy_mask_produces_exact_black_output_pixels() {
        let frame = frame_with_pixels(2, 1, |x, _y| {
            if x == 0 {
                [3, 2, 1, 255]
            } else {
                [6, 5, 4, 255]
            }
        });
        let projection = project(&frame, rect(0, 0, 2, 1), vec![rect(1, 0, 1, 1)]);

        assert_eq!(projection.as_bytes(), &[1, 2, 3, 0, 0, 0]);
    }

    #[test]
    fn overlapping_masks_remain_black() {
        let frame = solid_frame(3, 1, [30, 20, 10, 255]);
        let projection = project(
            &frame,
            rect(0, 0, 3, 1),
            vec![rect(0, 0, 2, 1), rect(1, 0, 2, 1)],
        );

        assert_eq!(projection.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn mask_boundary_is_half_open() {
        let frame = frame_with_pixels(3, 1, |x, _y| [small_test_byte(x), 0, 0, 255]);
        let projection = project(&frame, rect(0, 0, 3, 1), vec![rect(1, 0, 1, 1)]);

        assert_eq!(projection.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn out_of_bounds_mask_rejects() {
        let frame = solid_frame(2, 2, [0, 0, 0, 255]);
        assert_eq!(
            error_code(&frame, rect(0, 0, 2, 2), vec![rect(1, 1, 2, 1)]),
            ScreenVisionOutboundProjectionErrorCode::MaskInvalid
        );
    }

    #[test]
    fn more_than_64_masks_rejects() {
        let frame = solid_frame(1, 1, [0, 0, 0, 255]);
        let masks = vec![rect(0, 0, 1, 1); MAX_PRIVACY_MASK_RECTS + 1];

        assert_eq!(
            error_code(&frame, rect(0, 0, 1, 1), masks),
            ScreenVisionOutboundProjectionErrorCode::TooManyMasks
        );
    }

    #[test]
    fn mask_outside_crop_but_inside_frame_is_accepted_without_effect() {
        let frame = frame_with_pixels(3, 1, |x, _y| [small_test_byte(x + 1), 0, 0, 255]);
        let projection = project(&frame, rect(0, 0, 1, 1), vec![rect(2, 0, 1, 1)]);

        assert_eq!(projection.as_bytes(), &[0, 0, 1]);
    }

    #[test]
    fn masked_source_pixel_never_contributes_after_downscale() {
        let sensitive_x = 800;
        let frame = frame_with_pixels(1_601, 1, |x, _y| {
            if x == sensitive_x {
                [0, 0, 255, 255]
            } else {
                [255, 255, 255, 255]
            }
        });
        let projection = project(
            &frame,
            rect(0, 0, 1_601, 1),
            vec![rect(sensitive_x, 0, 1, 1)],
        );

        assert_eq!(projection.width(), MAX_OUTBOUND_IMAGE_EDGE);
        assert_eq!(projection.height(), 1);
        assert!(projection
            .as_bytes()
            .chunks_exact(3)
            .all(|pixel| pixel == [0, 0, 0] || pixel == [255, 255, 255]));
    }

    #[test]
    fn downscale_preserves_aspect_ratio() {
        let frame = solid_frame(2_001, 1_001, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 2_001, 1_001), vec![]);

        assert_eq!(projection.width(), 1_600);
        assert_eq!(projection.height(), 800);
        assert_eq!(u64::from(projection.width()) * 1_001, 1_600_u64 * 1_001);
        assert!(
            u64::from(projection.width()) * 1_001 - u64::from(projection.height()) * 2_001 <= 2_001
        );
    }

    #[test]
    fn projection_never_upscales() {
        let frame = solid_frame(2, 3, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 2, 3), vec![]);

        assert_eq!((projection.width(), projection.height()), (2, 3));
    }

    #[test]
    fn long_edge_is_bounded_by_1600() {
        let frame = solid_frame(1_601, 1, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 1_601, 1), vec![]);

        assert!(projection.width() <= MAX_OUTBOUND_IMAGE_EDGE);
        assert!(projection.height() <= MAX_OUTBOUND_IMAGE_EDGE);
        assert_eq!(projection.width(), 1_600);
    }

    #[test]
    fn output_pixels_are_bounded() {
        let frame = solid_frame(1_601, 1_600, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 1_601, 1_600), vec![]);
        let pixels = u64::from(projection.width()) * u64::from(projection.height());

        assert!(pixels <= MAX_OUTBOUND_IMAGE_PIXELS);
        assert_eq!(pixels, 2_558_400);
    }

    #[test]
    fn rgb_byte_size_is_exactly_width_times_height_times_three() {
        let frame = solid_frame(3, 2, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 3, 2), vec![]);

        assert_eq!(projection.as_bytes().len(), 3 * 2 * 3);
    }

    #[test]
    fn odd_dimensions_and_rounding_never_produce_zero_output_dimension() {
        let frame = solid_frame(1_601, 3, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 1_601, 3), vec![]);

        assert_eq!((projection.width(), projection.height()), (1_600, 2));
        assert!(projection.width() >= 1);
        assert!(projection.height() >= 1);
    }

    #[test]
    fn output_buffer_is_structurally_zeroizing() {
        fn assert_zeroizing_owner(_bytes: &Zeroizing<Vec<u8>>) {}

        let frame = solid_frame(1, 1, [1, 2, 3, 255]);
        let projection = project(&frame, rect(0, 0, 1, 1), vec![]);

        assert_zeroizing_owner(&projection.bytes);
    }

    #[test]
    fn source_frame_is_not_mutated() {
        let frame = frame_with_pixels(2, 2, |x, y| {
            [small_test_byte(x), small_test_byte(y), 9, 255]
        });
        let before = frame.clone();

        let _projection = project(&frame, rect(0, 0, 2, 2), vec![rect(1, 1, 1, 1)]);

        assert_eq!(frame, before);
    }

    #[test]
    fn same_input_and_plan_are_deterministic() {
        let frame = frame_with_pixels(4, 3, |x, y| {
            [
                small_test_byte(x),
                small_test_byte(y),
                small_test_byte(x + y),
                255,
            ]
        });
        let request = request(rect(0, 0, 4, 3), vec![rect(1, 1, 2, 1)]);

        let first =
            project_screen_frame(&frame, &request).expect("first projection should succeed");
        let second =
            project_screen_frame(&frame, &request).expect("second projection should succeed");

        assert_eq!(first.width(), second.width());
        assert_eq!(first.height(), second.height());
        assert_eq!(first.pixel_format(), second.pixel_format());
        assert_eq!(first.as_bytes(), second.as_bytes());
    }
}
