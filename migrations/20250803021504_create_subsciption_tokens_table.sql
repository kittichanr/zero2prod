-- Add migration script here
CREATE TABLE subscription_tokens (
    subscription_token TEXT PRIMARY KEY,
    subscriber_id UUID NOT NULL,
    FOREIGN KEY (subscriber_id) 
    REFERENCES subscriptions(id)
);
