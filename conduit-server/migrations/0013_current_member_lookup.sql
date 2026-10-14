CREATE INDEX room_current_membership_user ON room_current_state (state_key, room_id)
    WHERE type = 'm.room.member';
