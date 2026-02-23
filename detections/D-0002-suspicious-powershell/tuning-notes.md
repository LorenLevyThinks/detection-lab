# Tuning Guidance

## Known False Positives
- IT automation scripts
- Configuration management tools
- Software deployment frameworks

## Tuning Strategy
- Alert only when combined with suspicious parent process
- Increase severity if outbound network connection follows
- Suppress known admin hosts

## Escalation Criteria
- Encoded command with network call
- Base64 payload > 100 characters
- Parent process = Office application
