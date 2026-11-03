# Ollama

Local AI models served by Ollama: what's installed, what's loaded and how
much graphics memory it takes, downloading and removing models, and a quick
test prompt. Conduit's assistant can also use these models (Assistant and
agents); this module is about managing them.

**Setup.** Nothing for Ollama on the same machine (`http://127.0.0.1:11434`).
For another machine, its address, and a token (in the vault) only if
Ollama sits behind a proxy that asks for one. Ollama itself has no
sign-in, so don't expose it beyond your network.

| Action | Risk | Notes |
| --- | --- | --- |
| `models` | read | Name, size, family, parameters, quantization |
| `running` | read | Loaded models, graphics memory per model and in total, when each unloads |
| `pull` | write | Downloads or updates a model. Waits up to 10 minutes; a bigger download reports how far it got and continues where it left off when run again |
| `delete` | destructive | Removes a model; preview first. Download it again to get it back |
| `generate` | read | Up to 256 tokens from a model, with tokens per second, to check it works |
