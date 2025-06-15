// Base32 decoding
const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32lookup = (() => {
  const lookup = {};
  for (let i = 0; i < base32chars.length; i++) {
    lookup[base32chars[i]] = i;
  }
  return lookup;
})();

function base32decode(base32) {
  base32 = base32.replace(/=+$/, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const output = [];

  for (let i = 0; i < base32.length; i++) {
    const c = base32[i];
    if (!(c in base32lookup)) continue;

    value = (value << 5) | base32lookup[c];
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

// HMAC-SHA1 using Web Crypto API
async function hmacSha1(keyBytes, messageBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: { name: "SHA-1" } },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, messageBytes);

  return new Uint8Array(signature);
}

function getParameterByName(name, url = window.location.href) {
  name = name.replace(/[\[\]]/g, "\\$&");
  const regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)");
  const results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return "";
  return decodeURIComponent(results[2].replace(/\+/g, " "));
}

function updateShareLink(key) {
  const shareUrl = `${window.location.origin}${window.location.pathname
    }?key=${encodeURIComponent(key)}`;
  document.getElementById("share-url").textContent = shareUrl;
  document.getElementById("share-link").style.display = "block";
}

function copyToClipboard(elementId) {
  const element = document.getElementById(elementId);
  const textToCopy = element.textContent || element.innerText;

  navigator.clipboard
    .writeText(textToCopy)
    .then(() => {
      const originalText = element.textContent;
      element.textContent = "Copied!";
      setTimeout(() => {
        element.textContent = originalText;
      }, 2000);
    })
    .catch((err) => {
      console.error("Failed to copy: ", err);
      // Fallback for old browser
      const textarea = document.createElement("textarea");
      textarea.value = textToCopy;
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand("copy");
        element.textContent = "Copied!";
        setTimeout(() => {
          element.textContent = originalText;
        }, 2000);
      } catch (err) {
        console.error("Fallback copy failed: ", err);
      }
      document.body.removeChild(textarea);
    });
}

async function generateTOTP() {
  let secretKey = document.getElementById("secretKey").value.trim();

  // If no key in input, check URL parameter
  if (!secretKey) {
    const urlKey = getParameterByName("key");
    if (urlKey) {
      secretKey = urlKey;
      document.getElementById("secretKey").value = urlKey;
    } else {
      alert("Please enter a secret key");
      return;
    }
  }

  // Update share link when key changes
  updateShareLink(secretKey);

  try {
    // Decode base32 secret
    const keyBytes = base32decode(secretKey);

    // Get current timestamp in 30-second intervals
    const epoch = Math.floor(Date.now() / 1000);
    let time = Math.floor(epoch / 30);

    // Convert time to 8-byte array (big-endian)
    const timeBytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      timeBytes[i] = time & 0xff;
      time = time >>> 8;
    }

    // HMAC-SHA1 with the secret and time
    const hmacResult = await hmacSha1(keyBytes, timeBytes);

    // Dynamic truncation
    const offset = hmacResult[19] & 0xf;
    const binCode =
      ((hmacResult[offset] & 0x7f) << 24) |
      ((hmacResult[offset + 1] & 0xff) << 16) |
      ((hmacResult[offset + 2] & 0xff) << 8) |
      (hmacResult[offset + 3] & 0xff);

    // Generate 6-digit code
    const otp = binCode % 1000000;
    const code = ("000000" + otp).slice(-6);

    document.getElementById("code-value").textContent = code;
    document.getElementById("result").style.display = "flex";

    // Update timer
    updateTimer();
  } catch (e) {
    document.getElementById("result").style.display = "flex";
    document.getElementById(
      "code-value"
    ).textContent = `Error: ${e.message}`;
  }
}

function updateTimer() {
  const epoch = Math.floor(Date.now() / 1000);
  const remaining = 30 - (epoch % 30);

  document.getElementById(
    "timer"
  ).textContent = `Time remaining: ${remaining}s`;

  if (remaining <= 5) {
    setTimeout(generateTOTP, remaining * 1000);
  } else {
    setTimeout(updateTimer, 1000);
  }
}

// Generate code on page load
window.onload = function () {
  // Check for key in URL first
  const urlKey = getParameterByName("key");
  if (urlKey) {
    document.getElementById("secretKey").value = urlKey;
    document.getElementById("result").style.display = "flex";
    document.getElementById("share-link").style.display = "block";
    updateShareLink(urlKey);
  }
  generateTOTP();
};