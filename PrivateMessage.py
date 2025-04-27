from InitialMessage import InitialMessage, serialize_initial_message, deserialize_initial_message

from typing import TypedDict, Any


class PrivateMessage(TypedDict):
    sender: str
    receiver: str
    message: str | bytes | InitialMessage
    is_initial_message: bool
    timestamp: str
    profile_serialized_encrypted: bytes | None

def serialize_private_message(message: PrivateMessage) -> dict[str, Any]:
    if message["is_initial_message"]:
        return {"sender": message["sender"], "receiver": message["receiver"], "message": serialize_initial_message(message["message"]), "is_initial_message": message["is_initial_message"], "timestamp": message["timestamp"], "profile_serialized_encrypted": message["profile_serialized_encrypted"]}
    else:
        return {"sender": message["sender"], "receiver": message["receiver"], "message": message["message"], "is_initial_message": message["is_initial_message"], "timestamp": message["timestamp"], "profile_serialized_encrypted": message["profile_serialized_encrypted"]}


def deserialize_private_message(data: dict[str, Any]) -> PrivateMessage:
    if not isinstance(data, dict):
        raise TypeError("Deserialized object is not a dict")

    # Optionally check required keys
    expected_keys = {"sender", "receiver", "message", "is_initial_message", "timestamp"}
    if not expected_keys.issubset(data):
        raise ValueError("Deserialized dict does not match PrivateMessage structure")

    if data["is_initial_message"]:
        return PrivateMessage(sender=data["sender"], receiver=data["receiver"], message=deserialize_initial_message(data["message"]), is_initial_message=data["is_initial_message"], timestamp=data["timestamp"], profile_serialized_encrypted=data["profile_serialized_encrypted"])
    else:
        return PrivateMessage(sender=data["sender"], receiver=data["receiver"], message=data["message"], is_initial_message=data["is_initial_message"], timestamp=data["timestamp"], profile_serialized_encrypted=data["profile_serialized_encrypted"])

def list_messages(name: str, messages: dict[str, list[dict]]):
    # Check if *all* message lists are empty
    if not any(messages[sender] for sender in messages):
        print(f"No messages for {name}.")
        return

    print(f"\nMessages for {name}:")
    for sender, msg_list in messages.items():
        if not msg_list:
            continue  # Skip empty sender

        # Sort messages by timestamp
        msg_list.sort(key=lambda x: x["timestamp"])

        print(f"\tFrom {msg_list[0]["sender"]}:")
        for message in msg_list:
            print(f"\t\t({message['timestamp']}): {message['message']}")
