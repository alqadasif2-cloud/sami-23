import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  getCloudGitHubSettings,
  isValidProductionServerUrl,
  saveCloudGitHubSettings,
  firestoreClient,
} from './db.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');
const LOCAL_VAULT_FILE = path.resolve(DATA_DIR, '.vault_secret.enc');
const MASTER_SEED_FILE = path.resolve(DATA_DIR, '.vault_seed');

const GCP_SECRET_ID = 'sami-github-releases-credentials';
const METADATA_BASE = 'http://metadata.google.internal/computeMetadata/v1';
const GCP_CACHE_TTL_MS = 30_000;

interface StoredSecretPayload {
  token: string;
  updatedAt: number;
}

interface EncryptedVaultRecord {
  algorithm: 'aes-256-gcm';
  iv: string;
  tag: string;
  data: string;
  updatedAt: number;
}

export type VaultStorageMode =
  | 'gcp_secret_manager'
  | 'server_encrypted_vault'
  | 'server_env'
  | 'unconfigured';

export interface VaultPublicStatus {
  storageMode: VaultStorageMode;
  persistentVaultAvailable: boolean;
  secretManagerEnabled: boolean;
  cloudSettingsPersisted: boolean;
  hasSavedToken: boolean;
  tokenStatusAr: string;
  updatedAt: number | null;
  updatedBy: string | null;
  apiServerUrl: string;
  hostingVaultNoticeAr: string | null;
}

export interface ResolvedGitHubVaultCredentials {
  owner: string;
  repo: string;
  token: string;
  hasToken: boolean;
  apiServerUrl: string;
  vault: VaultPublicStatus;
}

let gcpProbeDoneAt = 0;
let gcpSecretManagerAvailable = false;
let gcpTargetProjectId: string | null = null;
let gcpCachedPayload: { payload: StoredSecretPayload | null; cachedAt: number } | null = null;

// Isolated runtime cache of active token
let activeVaultPayload: StoredSecretPayload | null = null;

// Isolated server-only set of active token strings used strictly by redactGitHubSecrets()
const redactionTokenSet = new Set<string>();

export function registerTokenForRedaction(token: string): void {
  const clean = token.trim();
  if (clean.length >= 4) {
    redactionTokenSet.add(clean);
  }
}

export function getKnownSecretTokensForRedaction(): string[] {
  const envTok1 = (process.env.GITHUB_TOKEN || '').trim();
  const envTok2 = (process.env.GITHUB_RELEASES_TOKEN || '').trim();
  if (envTok1.length >= 4) redactionTokenSet.add(envTok1);
  if (envTok2.length >= 4) redactionTokenSet.add(envTok2);
  if (activeVaultPayload?.token) {
    redactionTokenSet.add(activeVaultPayload.token);
  }
  return Array.from(redactionTokenSet);
}

function sha256ConstantTimeEqual(a: string, b: string): boolean {
  if (!a || !b) return false;
  const hashA = crypto.createHash('sha256').update(a, 'utf8').digest();
  const hashB = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

export function sanitizeGitHubSlug(val: string | undefined | null): string {
  return String(val || '')
    .trim()
    .replace(/^["']+|["']+$/g, '')
    .replace(/\.git$/i, '')
    .replace(/^\/+|\/+$/g, '');
}

export function parseOwnerAndRepoInput(rawOwner: string, rawRepo: string): { owner: string; repo: string } {
  let owner = sanitizeGitHubSlug(rawOwner);
  let repo = sanitizeGitHubSlug(rawRepo);

  const urlRegex = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s]+?)(?:\.git)?\/?$/i;
  const repoUrlMatch = repo.match(urlRegex);
  const ownerUrlMatch = owner.match(urlRegex);

  if (repoUrlMatch) {
    return {
      owner: sanitizeGitHubSlug(repoUrlMatch[1]),
      repo: sanitizeGitHubSlug(repoUrlMatch[2]),
    };
  }
  if (ownerUrlMatch) {
    return {
      owner: sanitizeGitHubSlug(ownerUrlMatch[1]),
      repo: sanitizeGitHubSlug(ownerUrlMatch[2]),
    };
  }
  if (!owner && repo.includes('/')) {
    const parts = repo.split('/').filter(Boolean);
    if (parts.length >= 2) {
      owner = sanitizeGitHubSlug(parts[0]);
      repo = sanitizeGitHubSlug(parts[1]);
    }
  } else if (repo.includes('/') && !repo.startsWith('http')) {
    const parts = repo.split('/').filter(Boolean);
    if (parts.length === 2 && (!owner || owner === parts[0])) {
      owner = sanitizeGitHubSlug(parts[0]);
      repo = sanitizeGitHubSlug(parts[1]);
    }
  }

  return { owner, repo };
}

// ============================================================================
// SERVER-SIDE AES-256-GCM ENCRYPTION KEY DERIVATION & ENCRYPTION ENGINE
// ============================================================================

function getOrCreateVaultKey(): Buffer {
  let seed = '';
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (fs.existsSync(MASTER_SEED_FILE)) {
      seed = fs.readFileSync(MASTER_SEED_FILE, 'utf8').trim();
    }
  } catch {}

  if (!seed || seed.length < 32) {
    seed = crypto.randomBytes(32).toString('hex');
    try {
      fs.writeFileSync(MASTER_SEED_FILE, seed, { mode: 0o600 });
    } catch {}
  }

  const salt = 'sami_app_vault_salt_2026_isolated_cloud_key';
  return crypto.scryptSync(seed, salt, 32);
}

function encryptTokenToVault(token: string): EncryptedVaultRecord {
  const key = getOrCreateVaultKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    algorithm: 'aes-256-gcm',
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex'),
    updatedAt: Date.now(),
  };
}

function decryptTokenFromVault(record: EncryptedVaultRecord): string | null {
  if (!record || record.algorithm !== 'aes-256-gcm' || !record.iv || !record.tag || !record.data) {
    return null;
  }
  try {
    const key = getOrCreateVaultKey();
    const iv = Buffer.from(record.iv, 'hex');
    const tag = Buffer.from(record.tag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = decipher.update(Buffer.from(record.data, 'hex'), undefined, 'utf8') + decipher.final('utf8');
    return decrypted.trim() || null;
  } catch {
    return null;
  }
}

// ============================================================================
// STORAGE TIER 1: GOOGLE CLOUD SECRET MANAGER (IF ENABLED IN GCP PROJECT)
// ============================================================================

async function fetchMetadataAccessToken(): Promise<{ accessToken: string; projectId: string } | null> {
  try {
    const headers = { 'Metadata-Flavor': 'Google' };
    const [projRes, tokRes] = await Promise.all([
      fetch(`${METADATA_BASE}/project/project-id`, {
        headers,
        signal: AbortSignal.timeout(2_000),
      }),
      fetch(`${METADATA_BASE}/instance/service-accounts/default/token`, {
        headers,
        signal: AbortSignal.timeout(2_000),
      }),
    ]);
    if (!tokRes.ok) return null;
    const tokJson: any = await tokRes.json().catch(() => null);
    const metaProj = projRes.ok ? (await projRes.text()).trim() : '';
    const projectId = (process.env.GCP_SECRET_MANAGER_PROJECT || metaProj || '').trim();
    if (!tokJson?.access_token || !projectId) return null;
    return { accessToken: String(tokJson.access_token), projectId };
  } catch {
    return null;
  }
}

async function probeGcpSecretManager(force = false): Promise<boolean> {
  if (!force && gcpProbeDoneAt > 0 && Date.now() - gcpProbeDoneAt < 60_000) {
    return gcpSecretManagerAvailable;
  }
  gcpProbeDoneAt = Date.now();

  const meta = await fetchMetadataAccessToken();
  if (!meta) {
    gcpSecretManagerAvailable = false;
    return false;
  }

  try {
    const res = await fetch(
      `https://secretmanager.googleapis.com/v1/projects/${encodeURIComponent(meta.projectId)}/secrets?pageSize=1`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${meta.accessToken}` },
        signal: AbortSignal.timeout(3_000),
      }
    );
    if (res.ok) {
      gcpSecretManagerAvailable = true;
      gcpTargetProjectId = meta.projectId;
      return true;
    }
    gcpSecretManagerAvailable = false;
    return false;
  } catch {
    gcpSecretManagerAvailable = false;
    return false;
  }
}

async function readFromGcpSecretManager(bypassCache = false): Promise<StoredSecretPayload | null> {
  if (!bypassCache && gcpCachedPayload && Date.now() - gcpCachedPayload.cachedAt < GCP_CACHE_TTL_MS) {
    return gcpCachedPayload.payload;
  }

  const ok = await probeGcpSecretManager(bypassCache);
  if (!ok || !gcpTargetProjectId) return null;
  const meta = await fetchMetadataAccessToken();
  if (!meta) return null;

  try {
    const res = await fetch(
      `https://secretmanager.googleapis.com/v1/projects/${encodeURIComponent(gcpTargetProjectId)}/secrets/${GCP_SECRET_ID}/versions/latest:access`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${meta.accessToken}` },
        signal: AbortSignal.timeout(4_000),
      }
    );
    if (!res.ok) {
      gcpCachedPayload = { payload: null, cachedAt: Date.now() };
      return null;
    }
    const data: any = await res.json();
    const b64 = data?.payload?.data;
    if (!b64) return null;
    const jsonStr = Buffer.from(String(b64), 'base64').toString('utf8');
    const parsed = JSON.parse(jsonStr) as any;
    const cleanTok = sanitizeGitHubSlug(parsed?.token);
    if (!cleanTok) return null;
    registerTokenForRedaction(cleanTok);
    const result: StoredSecretPayload = {
      token: cleanTok,
      updatedAt: Number(parsed?.updatedAt) || Date.now(),
    };
    gcpCachedPayload = { payload: result, cachedAt: Date.now() };
    return result;
  } catch {
    return null;
  }
}

async function writeToGcpSecretManager(payload: StoredSecretPayload): Promise<boolean> {
  const ok = await probeGcpSecretManager(true);
  if (!ok || !gcpTargetProjectId) return false;
  const meta = await fetchMetadataAccessToken();
  if (!meta) return false;

  const parent = `projects/${encodeURIComponent(gcpTargetProjectId)}`;
  const secretName = `${parent}/secrets/${GCP_SECRET_ID}`;
  const authHeaders = {
    Authorization: `Bearer ${meta.accessToken}`,
    'Content-Type': 'application/json',
  };

  try {
    const getSec = await fetch(`https://secretmanager.googleapis.com/v1/${secretName}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${meta.accessToken}` },
      signal: AbortSignal.timeout(4_000),
    });
    if (getSec.status === 404) {
      const createSec = await fetch(
        `https://secretmanager.googleapis.com/v1/${parent}/secrets?secretId=${GCP_SECRET_ID}`,
        {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ replication: { automatic: {} } }),
          signal: AbortSignal.timeout(5_000),
        }
      );
      if (!createSec.ok) return false;
    } else if (!getSec.ok) {
      return false;
    }

    const b64Data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    const addVer = await fetch(`https://secretmanager.googleapis.com/v1/${secretName}:addVersion`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ payload: { data: b64Data } }),
      signal: AbortSignal.timeout(5_000),
    });
    if (!addVer.ok) return false;

    gcpCachedPayload = null;
    return true;
  } catch {
    return false;
  }
}

// ============================================================================
// STORAGE TIER 2: SERVER-ENCRYPTED FILE & FIRESTORE SERVER SECRETS
// ============================================================================

function readFromLocalEncryptedFile(): StoredSecretPayload | null {
  try {
    if (!fs.existsSync(LOCAL_VAULT_FILE)) return null;
    const content = fs.readFileSync(LOCAL_VAULT_FILE, 'utf8').trim();
    if (!content) return null;
    const record = JSON.parse(content) as EncryptedVaultRecord;
    const decrypted = decryptTokenFromVault(record);
    if (!decrypted) return null;
    registerTokenForRedaction(decrypted);
    return { token: decrypted, updatedAt: record.updatedAt || Date.now() };
  } catch {
    return null;
  }
}

function writeToLocalEncryptedFile(token: string): boolean {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const encrypted = encryptTokenToVault(token);
    fs.writeFileSync(LOCAL_VAULT_FILE, JSON.stringify(encrypted), { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

async function readFromFirestoreServerSecrets(): Promise<StoredSecretPayload | null> {
  if (!firestoreClient) return null;
  try {
    const doc = await firestoreClient.collection('server_secrets').doc('github_credentials').get();
    if (!doc.exists) return null;
    const record = doc.data() as EncryptedVaultRecord;
    const decrypted = decryptTokenFromVault(record);
    if (!decrypted) return null;
    registerTokenForRedaction(decrypted);
    return { token: decrypted, updatedAt: record.updatedAt || Date.now() };
  } catch {
    return null;
  }
}

async function writeToFirestoreServerSecrets(token: string): Promise<boolean> {
  if (!firestoreClient) return false;
  try {
    const encrypted = encryptTokenToVault(token);
    await firestoreClient.collection('server_secrets').doc('github_credentials').set(encrypted, { merge: true });
    return true;
  } catch {
    return false;
  }
}

// ============================================================================
// STORAGE TIER 3: SERVER ENVIRONMENT SECRETS
// ============================================================================

function readPermanentEnvCredentials(): { owner: string; repo: string; token: string } {
  const rawOwner = (process.env.GITHUB_RELEASES_OWNER || process.env.GITHUB_OWNER || '').trim();
  const rawRepo = (process.env.GITHUB_RELEASES_REPO || process.env.GITHUB_REPO || '').trim();
  const parsed = parseOwnerAndRepoInput(rawOwner, rawRepo);
  const token = sanitizeGitHubSlug(process.env.GITHUB_RELEASES_TOKEN || process.env.GITHUB_TOKEN || '');
  if (token) registerTokenForRedaction(token);
  return {
    owner: parsed.owner,
    repo: parsed.repo,
    token,
  };
}

// ============================================================================
// RESOLVE & SAVE GITHUB CREDENTIALS
// ============================================================================

export async function getResolvedGitHubCredentials(forceFresh = false): Promise<ResolvedGitHubVaultCredentials> {
  const [secretManagerEnabled, cloudSettings] = await Promise.all([
    probeGcpSecretManager(forceFresh),
    getCloudGitHubSettings(forceFresh),
  ]);

  const envCreds = readPermanentEnvCredentials();

  let resolvedToken = '';
  let storageMode: VaultStorageMode = 'unconfigured';
  let updatedAt: number | null = cloudSettings.updatedAt || null;

  // 1. Check memory cache
  if (!forceFresh && activeVaultPayload?.token) {
    resolvedToken = activeVaultPayload.token;
    storageMode = 'server_encrypted_vault';
    updatedAt = activeVaultPayload.updatedAt;
  }

  // 2. Check GCP Secret Manager if available
  if (!resolvedToken && secretManagerEnabled) {
    const gcpSecret = await readFromGcpSecretManager(forceFresh);
    if (gcpSecret?.token) {
      resolvedToken = gcpSecret.token;
      storageMode = 'gcp_secret_manager';
      updatedAt = gcpSecret.updatedAt;
      activeVaultPayload = gcpSecret;
    }
  }

  // 3. Check local encrypted file vault
  if (!resolvedToken) {
    const localVault = readFromLocalEncryptedFile();
    if (localVault?.token) {
      resolvedToken = localVault.token;
      storageMode = 'server_encrypted_vault';
      updatedAt = localVault.updatedAt;
      activeVaultPayload = localVault;
    }
  }

  // 4. Check Firestore server-secrets document
  if (!resolvedToken) {
    const firestoreVault = await readFromFirestoreServerSecrets();
    if (firestoreVault?.token) {
      resolvedToken = firestoreVault.token;
      storageMode = 'server_encrypted_vault';
      updatedAt = firestoreVault.updatedAt;
      activeVaultPayload = firestoreVault;
    }
  }

  // 5. Check permanent server environment variables
  if (!resolvedToken && envCreds.token) {
    resolvedToken = envCreds.token;
    storageMode = 'server_env';
    activeVaultPayload = { token: resolvedToken, updatedAt: Date.now() };
  }

  if (resolvedToken) {
    registerTokenForRedaction(resolvedToken);
  }

  // Non-secret Owner & Repo come dynamically from Cloud Firestore (`app_updates/latest`), or server env
  const resolvedOwner = cloudSettings.githubOwner || envCreds.owner || '';
  const resolvedRepo = cloudSettings.githubRepo || envCreds.repo || '';

  const hasSavedToken = resolvedToken.length > 0;
  const persistentVaultAvailable = hasSavedToken || secretManagerEnabled || true;

  return {
    owner: resolvedOwner,
    repo: resolvedRepo,
    token: resolvedToken,
    hasToken: hasSavedToken,
    apiServerUrl: cloudSettings.apiServerUrl,
    vault: {
      storageMode,
      persistentVaultAvailable,
      secretManagerEnabled,
      cloudSettingsPersisted: cloudSettings.source === 'firestore',
      hasSavedToken,
      tokenStatusAr: hasSavedToken ? 'التوكن محفوظ ومشفر في مخزن الخادم' : 'التوكن غير محفوظ',
      updatedAt,
      updatedBy: cloudSettings.updatedBy,
      apiServerUrl: cloudSettings.apiServerUrl,
      hostingVaultNoticeAr: null,
    },
  };
}

export async function saveGitHubCredentialsToVault(input: {
  owner: string;
  repo: string;
  token?: string;
  apiServerUrl?: string;
  updatedBy?: string;
}): Promise<{
  owner: string;
  repo: string;
  hasToken: boolean;
  apiServerUrl: string;
  vault: VaultPublicStatus;
}> {
  const parsed = parseOwnerAndRepoInput(input.owner, input.repo);
  const slugRegex = /^[A-Za-z0-9._-]+$/;

  if (!parsed.owner || !slugRegex.test(parsed.owner)) {
    throw new Error('يرجى إدخال اسم مالك مستودع GitHub صالح في حقل GITHUB_OWNER');
  }
  if (!parsed.repo || !slugRegex.test(parsed.repo)) {
    throw new Error('يرجى إدخال اسم مستودع GitHub صالح في حقل GITHUB_REPO');
  }

  let cleanApiServerUrl: string | undefined;
  if (input.apiServerUrl !== undefined && String(input.apiServerUrl).trim() !== '') {
    const validUrl = isValidProductionServerUrl(input.apiServerUrl);
    if (validUrl) {
      cleanApiServerUrl = validUrl;
    }
  }

  const incomingToken = sanitizeGitHubSlug(input.token);
  if (incomingToken && /\s/.test(incomingToken)) {
    throw new Error('صيغة التوكن المدخل في GITHUB_TOKEN غير صالحة (يجب ألا يحتوي على مسافات)');
  }

  const current = await getResolvedGitHubCredentials(true);

  // STEP 1: Process and store secret token
  if (!incomingToken) {
    if (!current.hasToken) {
      throw new Error('يرجى إدخال التوكن السري (GITHUB_TOKEN) لحفظ الإعدادات لأول مرة');
    }
    // Retain existing token
  } else {
    registerTokenForRedaction(incomingToken);

    // Save encrypted payload locally and in server secrets
    writeToLocalEncryptedFile(incomingToken);
    await writeToFirestoreServerSecrets(incomingToken);

    // If GCP Secret Manager is enabled on the cloud project, update it too
    await writeToGcpSecretManager({
      token: incomingToken,
      updatedAt: Date.now(),
    }).catch(() => {});

    // Update runtime memory cache
    activeVaultPayload = {
      token: incomingToken,
      updatedAt: Date.now(),
    };
  }

  // STEP 2: Persist non-secret GITHUB_OWNER and GITHUB_REPO in Cloud Firestore
  await saveCloudGitHubSettings({
    githubOwner: parsed.owner,
    githubRepo: parsed.repo,
    apiServerUrl: cleanApiServerUrl,
    updatedBy: input.updatedBy,
  });

  // STEP 3: Verify fresh state
  const verified = await getResolvedGitHubCredentials(true);
  if (!verified.hasToken || verified.owner !== parsed.owner || verified.repo !== parsed.repo) {
    throw new Error('تعذر التحقق النهائي من حفظ إعدادات GitHub في الخادم');
  }

  return {
    owner: verified.owner,
    repo: verified.repo,
    hasToken: true,
    apiServerUrl: verified.apiServerUrl,
    vault: verified.vault,
  };
}
