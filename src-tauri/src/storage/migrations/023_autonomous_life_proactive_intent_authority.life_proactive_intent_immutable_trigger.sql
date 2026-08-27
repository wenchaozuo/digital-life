CREATE TRIGGER life_proactive_intent_immutable_guard
BEFORE UPDATE ON life_proactive_intent
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.intent_id IS NOT OLD.intent_id
     OR NEW.life_id IS NOT OLD.life_id
     OR NEW.goal_id IS NOT OLD.goal_id
     OR NEW.intent_kind IS NOT OLD.intent_kind
     OR NEW.importance IS NOT OLD.importance
     OR NEW.user_relevance IS NOT OLD.user_relevance
     OR NEW.self_desire IS NOT OLD.self_desire
     OR NEW.interruption_cost IS NOT OLD.interruption_cost
     OR NEW.focus_state IS NOT OLD.focus_state
     OR NEW.acceptance_score IS NOT OLD.acceptance_score
     OR NEW.recent_interaction_seconds IS NOT OLD.recent_interaction_seconds
     OR NEW.created_by_kind IS NOT OLD.created_by_kind
     OR NEW.created_at IS NOT OLD.created_at
     OR NEW.expires_at IS NOT OLD.expires_at
     OR NEW.intent_version IS NOT OLD.intent_version
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'LIFE_PROACTIVE_INTENT_IMMUTABLE');
END;
