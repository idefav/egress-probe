/* No persistent credential, SDP or ICE password is stored or exported. */
'use strict';
const output = document.querySelector('#status');
let cancelled = false, current;
document.querySelector('#cancel').onclick = () => { cancelled = true; current?.close(); output.textContent = '已取消 / Cancelled; return to v2rayN to cancel remaining checks.'; };
window.addEventListener('pagehide', () => { cancelled = true; current?.close(); });
const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
async function run(ticket, key, serverId) {
  const started = performance.now();
  const candidates = new Set(); let pc, timer;
  const post = async (action, body) => {
    const response = await fetch(`/v1/webrtc/${ticket.id}/${action}`, {
      method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
      headers: {'Content-Type': 'application/json', Authorization: `Probe ${ticket.nonce}`},
      body: JSON.stringify(body), signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) throw new Error(`Signaling ${response.status}: ${(await response.text()).slice(0,256)}`);
    return response;
  };
  const report = {state: 'failed', candidates: [], browser: navigator.userAgent.slice(0,256)};
  try {
    if (!window.RTCPeerConnection || !window.crypto?.subtle) { report.state = 'unsupported'; throw new Error('Browser WebRTC unavailable'); }
    pc = current = new RTCPeerConnection({iceServers: [], iceTransportPolicy: 'all'});
    // No third-party STUN is required: the public ICE-lite peer checks the real path.
    pc.onicecandidate = ({candidate: c}) => {
      if (c && candidates.size < 64) candidates.add(`${c.type} ${c.protocol} ${c.address}:${c.port}`.slice(0,256));
    };
    const dc = pc.createDataChannel('egress-probe');
    const received = new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('ICE/DTLS/data channel timeout')), 45000);
      dc.onopen = () => dc.send(JSON.stringify({id: ticket.id, nonce: ticket.nonce}));
      dc.onmessage = e => resolve(e.data);
      pc.onconnectionstatechange = () => { if (['failed','closed'].includes(pc.connectionState)) reject(new Error('Connection '+pc.connectionState)); };
    });
    // Attach immediately, even if signaling fails before awaiting the response.
    received.catch(() => {});
    const gathered = new Promise(resolve => {
      const deadline = setTimeout(resolve, 5000);
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') { clearTimeout(deadline); resolve(); } };
    });
    await pc.setLocalDescription(await pc.createOffer()); await gathered;
    if (cancelled) throw new Error('Cancelled');
    const answer = await (await post('offer', pc.localDescription)).json();
    await pc.setRemoteDescription(answer);
    const raw = await received;
    if (typeof raw !== 'string' || raw.length > 16384) throw new Error('Invalid receipt');
    const receipt = JSON.parse(raw), payload = decode(receipt.payload);
    if (!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'}, key, decode(receipt.signature), payload)) throw new Error('Invalid signature');
    const obs = JSON.parse(new TextDecoder().decode(payload));
    if (obs.serverId !== serverId || obs.probeId !== ticket.id || obs.nonce !== ticket.nonce || obs.sessionId !== ticket.sessionId || obs.kind !== 'webrtc' || obs.protocol !== 'WebRTC/DTLS/SCTP') throw new Error('Receipt does not match');
    report.state = 'complete'; report.receipt = receipt;
    output.textContent += `\n${ticket.id}: signed IPv4 egress ${obs.peerIp}:${obs.peerPort}`;
  } catch (error) {
    report.error = error.message.slice(0,512);
    output.textContent += '\n' + error.message;
  } finally {
    clearTimeout(timer); pc?.close(); current = null;
    report.candidates = [...candidates];
    report.elapsed = Math.min(180000, performance.now()-started);
    await post('complete', report);
  }
}
(async () => {
  try {
    const fragment = location.hash.slice(1); history.replaceState(null, '', location.pathname);
    if (!fragment) throw new Error('请从 v2rayN 的“浏览器 WebRTC”按钮启动检查 / Start from Browser WebRTC in v2rayN.');
    if (fragment.length > 20000) throw new Error('Invalid launch data');
    const input = JSON.parse(new TextDecoder().decode(decode(fragment)));
    if (!Array.isArray(input.tickets) || input.tickets.length < 1 || input.tickets.length > 10) throw new Error('Invalid tickets');
    const key = await crypto.subtle.importKey('spki', decode(input.publicKey), {name:'ECDSA',namedCurve:'P-256'}, false, ['verify']);
    output.textContent = '正在检查，请保持页面打开 / Checking; keep this page open.';
    for (const ticket of input.tickets) { if (cancelled) break; await run(ticket, key, input.serverId); }
    if (!cancelled) output.textContent += '\n完成，请返回 v2rayN 查看出口比较 / Finished; return to v2rayN for egress comparison.';
  } catch (error) { output.textContent += '\n' + error.message; }
})();
