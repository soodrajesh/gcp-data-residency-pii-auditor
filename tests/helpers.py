import json

from pii.llm import LLM, LLMResult

# Synthetic personal data. None of it belongs to a real person.
EMAILS = [
    "alice.nguyen@example.com",
    "bob.okafor@example.org",
    "carol.silva@example.net",
    "dan.petrov@example.io",
]
PHONES = ["(415) 555-2671", "(212) 555-0187", "(303) 555-0142", "(206) 555-0199"]
SSNS = ["078-05-1120", "219-09-9999", "123-45-6789", "457-55-5462"]
CARDS = ["4111 1111 1111 1111", "5500 0000 0000 0004", "3400 0000 0000 009", "6011 0000 0000 0004"]
IPS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
ALL = EMAILS + PHONES + SSNS + CARDS + IPS


class ScriptedLLM(LLM):
    name, model = "scripted", "scripted-1"

    def __init__(self, reply=None, *, raises=None):
        self.reply, self.raises, self.calls, self.seen = reply, raises, 0, []

    async def complete_json(self, system, user, max_tokens=1200):
        self.calls += 1
        self.seen.append(user)
        if self.raises:
            raise self.raises
        r = self.reply(json.loads(user)) if callable(self.reply) else self.reply
        return LLMResult(r if isinstance(r, str) else json.dumps(r), 50, 20, 0.0005)


def ds_meta(name="customers", location="EU", access=None, cmek=False):
    d = {
        "datasetReference": {"datasetId": name},
        "location": location,
        "access": access or [{"role": "OWNER", "userByEmail": "owner@example.com"}],
    }
    if cmek:
        d["defaultEncryptionConfiguration"] = {
            "kmsKeyName": "projects/p/locations/eu/keyRings/k/cryptoKeys/c"
        }
    return d


def table_meta(fields, **kw):
    return {
        "schema": {"fields": [{"name": n, "type": t} for n, t in fields]},
        "numRows": "100",
        "numBytes": "4096",
        **kw,
    }
