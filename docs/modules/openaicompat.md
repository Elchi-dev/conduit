# OpenAI-compatible server

Any server that speaks the OpenAI API: LM Studio, LocalAI, vLLM,
llama.cpp's `llama-server`, Jan, text-generation-webui, Ollama's `/v1`
and hosted ones. It lists the models the server offers, checks it
answers, and sends a chat message with the answer length capped by a
setting. Conduit's assistant can also use these servers (Assistant and
agents); this module is for checking and trying them.

**Setup.** The API base, the part before `/models`:

| Server | Usual address |
| --- | --- |
| LM Studio | `http://127.0.0.1:1234/v1` |
| llama.cpp, LocalAI | `http://127.0.0.1:8080/v1` |
| vLLM | `http://127.0.0.1:8000/v1` |
| Jan | `http://127.0.0.1:1337/v1` |

An API key (in the vault) only if the server asks for one. **Max tokens**
(512 by default, at most 8192) caps every chat answer; **timeout** (120
seconds by default, 5 to 600) bounds one chat.

| Action | Risk | Notes |
| --- | --- | --- |
| `models` | read | Model ids with their owner where the server says. |
| `chat` | write, sensitive | Sends `prompt` (up to 16,000 characters) and an optional `system` prompt to `model`, with optional `temperature` (0 to 2) and `maxTokens` (at most the instance's cap, which is also the default). Returns the answer, reasoning text when the server gives it, finish reason, token counts and how long it took. |

**Why chat is write and sensitive.** It changes nothing, but every call
uses the server's compute, and on a paid endpoint it costs money; as a
read, an agent with read-only access could run up a bill or tie up a GPU.
Prompts and answers can hold private material, so the audit log keeps
only field names. The cap is a setting rather than an input, so an agent
can ask for less but never more.

**Security.** Requests go only to the configured host: request paths are
fixed (`/models`, `/chat/completions`), redirects are followed within the
same host only and never from https to http, and the address can't carry
a user, query or fragment. Model ids are checked before a request.
Health is `degraded` when the server answers but offers no model.
