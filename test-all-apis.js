// ZerOn MoA — Full API Connectivity Test
// Run: node test-all-apis.js
require('dotenv').config();

const results = {};

// ─── 1. GEMINI ──────────────────────────────────────────────────────────────
async function testGemini() {
  try {
    const { GoogleGenerativeAI } = require('@google/generative-ai');
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: 'gemini-3.5-flash' });
    const result = await model.generateContent('Reply with exactly: GEMINI OK');
    const text = result.response.text().trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 2. NVIDIA / DeepSeek ───────────────────────────────────────────────────
async function testNVIDIA() {
  try {
    const response = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'meta/llama-3.1-8b-instruct',
        messages: [{ role: 'user', content: 'Reply with exactly: NVIDIA OK' }],
        max_tokens: 20,
        temperature: 0,
        stream: false
      })
    });
    const data = await response.json();
    if (!response.ok) return { status: '❌ FAIL', error: JSON.stringify(data).slice(0, 200) };
    const text = data.choices?.[0]?.message?.content?.trim();
    return { status: '✅ PASS', response: text, model: data.model };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 3. GROQ ────────────────────────────────────────────────────────────────
async function testGroq() {
  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: 'Reply with exactly: GROQ OK' }],
        max_tokens: 20,
        temperature: 0
      })
    });
    const data = await response.json();
    if (!response.ok) return { status: '❌ FAIL', error: JSON.stringify(data) };
    const text = data.choices?.[0]?.message?.content?.trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 4. COHERE ──────────────────────────────────────────────────────────────
async function testCohere() {
  try {
    const response = await fetch('https://api.cohere.com/v2/chat', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.COHERE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'command-r-08-2024',
        messages: [{ role: 'user', content: 'Reply with exactly: COHERE OK' }],
        max_tokens: 20
      })
    });
    const data = await response.json();
    if (!response.ok) return { status: '❌ FAIL', error: JSON.stringify(data) };
    const text = data.message?.content?.[0]?.text?.trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 5. CEREBRAS ────────────────────────────────────────────────────────────
async function testCerebras() {
  try {
    const response = await fetch('https://api.cerebras.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.CEREBRAS_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'gpt-oss-120b',
        messages: [{ role: 'user', content: 'Reply with exactly: CEREBRAS OK' }],
        max_tokens: 20,
        temperature: 0
      })
    });
    const data = await response.json();
    if (!response.ok) return { status: '❌ FAIL', error: JSON.stringify(data) };
    const text = data.choices?.[0]?.message?.content?.trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 6. TOGETHER AI ─────────────────────────────────────────────────────────
async function testTogether() {
  try {
    const response = await fetch('https://api.together.xyz/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.TOGETHER_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'mistralai/Mistral-7B-Instruct-v0.3',
        messages: [{ role: 'user', content: 'Reply with exactly: TOGETHER OK' }],
        max_tokens: 20,
        temperature: 0
      })
    });
    const data = await response.json();
    if (!response.ok) return { status: '❌ FAIL', error: JSON.stringify(data) };
    const text = data.choices?.[0]?.message?.content?.trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 7. SAMBANOVA ───────────────────────────────────────────────────────────
async function testSambaNova() {
  try {
    const response = await fetch('https://api.sambanova.ai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.SAMBANOVA_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'Meta-Llama-3.3-70B-Instruct',
        messages: [{ role: 'user', content: 'Reply with exactly: SAMBANOVA OK' }],
        max_tokens: 50,
        temperature: 0
      })
    });
    const data = await response.json();
    if (!response.ok) return { status: '❌ FAIL', error: JSON.stringify(data) };
    const text = data.choices?.[0]?.message?.content?.trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── 8. CLOUDFLARE ──────────────────────────────────────────────────────────
async function testCloudflare() {
  try {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/@cf/meta/llama-3.1-8b-instruct`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          messages: [{ role: 'user', content: 'Reply with exactly: CLOUDFLARE OK' }],
          max_tokens: 20
        })
      }
    );
    const data = await response.json();
    if (!data.success) return { status: '❌ FAIL', error: JSON.stringify(data.errors) };
    const text = data.result?.response?.trim();
    return { status: '✅ PASS', response: text };
  } catch (e) {
    return { status: '❌ FAIL', error: e.message };
  }
}

// ─── RUN ALL TESTS IN PARALLEL ──────────────────────────────────────────────
async function runAllTests() {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║       ZerOn MoA — API Connectivity Test          ║');
  console.log('╚══════════════════════════════════════════════════╝\n');
  console.log('Testing all 8 AI providers simultaneously...\n');

  const tests = {
    'Gemini (Master Orchestrator)':    testGemini(),
    'NVIDIA/DeepSeek (SQLi Agent)':    testNVIDIA(),
    'Groq (XSS Agent)':                testGroq(),
    'Cohere (Header Agent)':           testCohere(),
    'Cerebras (Speed Backup)':         testCerebras(),
    'Together AI (Reflection Judge)':  testTogether(),
    'SambaNova (Recon Backup)':        testSambaNova(),
    'Cloudflare (Rate-limit Fallback)':testCloudflare()
  };

  const entries = Object.entries(tests);
  const results = await Promise.allSettled(entries.map(([, p]) => p));

  let pass = 0, fail = 0;
  results.forEach((result, i) => {
    const name = entries[i][0];
    const data = result.status === 'fulfilled' ? result.value : { status: '❌ FAIL', error: result.reason?.message };
    const icon = data.status.startsWith('✅') ? '✅' : '❌';
    if (icon === '✅') pass++; else fail++;
    console.log(`${data.status}  ${name}`);
    if (data.response) console.log(`         Response: "${data.response}"`);
    if (data.error)    console.log(`         Error:    ${data.error}`);
    console.log();
  });

  console.log('─'.repeat(52));
  console.log(`  TOTAL: ${pass} passed, ${fail} failed out of 8 providers`);
  console.log('─'.repeat(52));
  
  if (fail === 0) {
    console.log('\n🚀 ALL SYSTEMS GO — Ready to build the agent swarm!\n');
  } else {
    console.log(`\n⚠️  Fix the ${fail} failing API(s) before building.\n`);
  }
}

runAllTests().catch(console.error);
