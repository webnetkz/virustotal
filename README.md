# VirusTotal Chrome Extension

Chrome extension (Manifest V3) for:
- checking the current website URL in VirusTotal
- checking a local file in VirusTotal

## Files

- `manifest.json` - extension manifest
- `background.js` - VirusTotal API integration
- `popup.html`, `popup.css`, `popup.js` - popup interface
- `options.html`, `options.js` - API key settings

## How to run

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select this folder:
   - `/Users/mac/Desktop/VirusTotal`
4. Open extension **Options** and paste your VirusTotal API key.
5. Open popup:
   - Click **Check Site** to scan current tab URL
   - Select a file and click **Check File**

## Notes

- URL checks first try existing report, then request a new analysis if needed.
- File checks first try SHA-256 report lookup, then upload for analysis if not found.
- VirusTotal rate limits depend on your API plan.
