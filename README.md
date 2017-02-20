# Beacon over SMS

Receive and rebroadcast SMS messages with a short veto delay.

## use

Send a text to a number registered with Plivo, and Beacon will forward it to a set group of vetoers. If it's appoved, or not vetoed in a short amount of time, then it will be sent out to all subscribers.

## spin up your own

### tech

Uses [plivo][] for SMS receipt and Flask for logic.

### requirements

- a [plivo][] account and phone number (most are $0.80 USD)

### setting up

lol idk

[plivo]: (https://plivo.com/)
