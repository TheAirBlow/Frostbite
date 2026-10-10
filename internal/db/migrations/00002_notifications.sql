-- +goose Up

-- Remembers which alerts went out, so a restart or a restore never repeats them.
CREATE TABLE notification_log (
    kind     TEXT NOT NULL,
    key      TEXT NOT NULL,
    sent_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key)
);

CREATE INDEX notification_log_sent_idx ON notification_log (sent_at);

-- +goose Down

DROP TABLE notification_log;
