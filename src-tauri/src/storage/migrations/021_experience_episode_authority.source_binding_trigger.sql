CREATE TRIGGER experience_episode_source_binding_guard
BEFORE INSERT ON experience_episode
WHEN digital_life_writer_epoch() IS 1
 AND (
     NEW.episode_id <> 'experience-conversation:' || NEW.life_id || ':' || NEW.conversation_id || ':' || NEW.turn_id
     OR NEW.source_ref <> NEW.conversation_id || ':' || NEW.turn_id
     OR NEW.created_at <> NEW.ended_at
     OR NOT EXISTS (
         SELECT 1
         FROM conversation_message
         WHERE id = NEW.user_message_id
           AND conversation_id = NEW.conversation_id
           AND life_id = NEW.life_id
           AND turn_id = NEW.turn_id
           AND role = 'user'
           AND created_at = NEW.started_at
     )
     OR NOT EXISTS (
         SELECT 1
         FROM conversation_message
         WHERE id = NEW.assistant_message_id
           AND conversation_id = NEW.conversation_id
           AND life_id = NEW.life_id
           AND turn_id = NEW.turn_id
           AND role = 'assistant'
           AND created_at = NEW.ended_at
     )
 )
BEGIN
    SELECT RAISE(ROLLBACK, 'EXPERIENCE_EPISODE_SOURCE_BINDING_MISMATCH');
END;
