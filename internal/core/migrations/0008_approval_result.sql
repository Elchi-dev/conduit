-- The audit entry of the call an approval let through, once it ran.
ALTER TABLE approvals ADD COLUMN result_seq INTEGER;
