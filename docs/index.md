<div class="page-wrapper">

<h1>🧠 Cyber Threat Intelligence Hub</h1>
<p class="timestamp">Generated on 2025-07-27 08:44 UTC</p>

Welcome to your personal CTI hub — your command center for monitoring fresh cyber threat intelligence from public sources.
<hr>
<table>
  <tr>
    <td><a href='./otx.md'><strong>👽 AlienVault OTX</strong><br/><em>Hashes and pulses from AlienVault OTX feed.</em></a></td>
    <td><a href='./malshare.md'><strong>🧬 Malshare</strong><br/><em>Hashes of malware binaries recently observed in the wild.</em></a></td>
  </tr>
  <tr>
    <td><a href='./abuseipdb.md'><strong>🚨 AbuseIPDB</strong><br/><em>IP addresses reported for abusive behavior.</em></a></td>
    <td><a href='./urlhaus.md'><strong>🌐 URLHaus</strong><br/><em>Malicious URLs reported by URLHaus.</em></a></td>
  </tr>
</table>
<hr>
<p><strong>Coming soon:</strong></p>
<ul>
<li>📄 Blog posts & incident analysis</li>
<li>💼 Resume and project portfolio</li>
<li>🛠 Tools and OSINT resources</li>
</ul>

</div>

<script>
const toggleTheme = () => {
  document.body.classList.toggle('dark-mode');
};
</script>

<style>
body {
  font-family: 'Segoe UI', sans-serif;
  margin: 2rem;
  color: #222;
  background: #fff;
  transition: background 0.3s, color 0.3s;
}
.dark-mode {
  background: #121212;
  color: #ddd;
}
.page-wrapper {
  max-width: 900px;
  margin: auto;
}
.timestamp {
  color: gray;
  font-size: 0.9em;
  margin-bottom: 1.5em;
}
h1 {
  font-size: 2em;
  margin-bottom: 0.3em;
}
pre, code {
  background-color: #f6f8fa;
  padding: 0.5em;
  display: block;
  border-radius: 6px;
  overflow-x: auto;
}
a {
  color: #0366d6;
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
button {
  position: fixed;
  top: 1rem;
  right: 1rem;
  background: #0366d6;
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  z-index: 1000;
}
</style>

<button onclick="toggleTheme()">🌓 Toggle Theme</button>
