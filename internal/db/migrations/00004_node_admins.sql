-- +goose Up

-- A node admin manages only the nodes listed here and what runs on them.
ALTER TABLE admins DROP CONSTRAINT admins_role_check;
ALTER TABLE admins ADD CONSTRAINT admins_role_check CHECK (role IN ('owner', 'admin', 'reseller', 'node_admin'));

CREATE TABLE admin_nodes (
    admin_id  BIGINT NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    node_id   BIGINT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    PRIMARY KEY (admin_id, node_id)
);

-- +goose Down

DROP TABLE admin_nodes;
UPDATE admins SET role = 'admin' WHERE role = 'node_admin';
ALTER TABLE admins DROP CONSTRAINT admins_role_check;
ALTER TABLE admins ADD CONSTRAINT admins_role_check CHECK (role IN ('owner', 'admin', 'reseller'));
