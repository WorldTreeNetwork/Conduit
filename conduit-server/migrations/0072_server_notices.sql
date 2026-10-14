-- Server notices (conduit-y99.41): exactly one notices room per user.
CREATE TABLE server_notice_rooms (
    user_id  TEXT PRIMARY KEY REFERENCES accounts(user_id),
    room_id  TEXT NOT NULL UNIQUE
);
