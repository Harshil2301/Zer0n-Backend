// Use native fetch (Node 18+) or fall back to node-fetch
const fetch = globalThis.fetch || require('node-fetch');

/**
 * Cloudflare AI Global Fallback
 * Triggered on 429 rate limits from primary agent APIs (NVIDIA, Groq, Cohere)
 */
async function askCloudflare(prompt) {
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
  const token = process.env.CLOUDFLARE_API_TOKEN;
  
  if (!accountId || !token) {
    throw new Error('Cloudflare credentials missing in .env');
  }

  const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/@cf/meta/llama-3.1-8b-instruct`, {
    method: 'POST',
    headers: { 
      'Authorization': `Bearer ${token}`, 
      'Content-Type': 'application/json' 
    },
    body: JSON.stringify({ 
      messages: [{ role: 'user', content: prompt }] 
    })
  });

  const data = await res.json();
  if (!data.success) {
    throw new Error(`Cloudflare AI failed: ${JSON.stringify(data.errors)}`);
  }
  
  return data.result.response;
}

module.exports = askCloudflare;
