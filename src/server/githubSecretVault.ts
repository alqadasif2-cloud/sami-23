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
const LEGACY_VAULT_FILE = path.resolve(DATA_DIR, '.vault_secret.enc');
const LEGACY_SEED_FILE = path.resolve(DATA_DIR, '.vault_seed');

// Google Cloud Secret Manager Secret Identifiers
export const GCP_SECRET_MANAGER_AES_KEY_ID = 'sami-aes256-vault-key';
export const GCP_SECRET_MANAGER_TOKEN_ID = 'sami-github-releases-credentials';
const METADATA_BASE = 'http://metadata.google.internal/computeMetadata/v1';
const GCP_CACHE_TTL_MS = 60_000;

interface StoredSecretPayload {
  token: string;
  updatedAt: number;
}

export interface EncryptedVaultRecord {
  algorithm: 'aes-256-gcm';
  iv: string;
  tag: string;
  data: string;
  updatedAt: number;
}

export type VaultStorageMode =
  | 'gcp_secret_manager'
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
  serviceAccountEmail?: string | null;
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

interface GcpServiceAccountAuth {
  accessToken: string;
  projectId: string;
  serviceAccountEmail: string;
}

// In-memory cache for the 256-bit AES key fetched from Secret Manager (never stored on disk)
let cachedSecretManagerAesKey: Buffer | null = null;
let lastKeyFetchTime = 0;

// In-memory cache for active token payload (never stored on disk)
let activeVaultPayload: StoredSecretPayload | null = null;

let gcpProbeDoneAt = 0;
let gcpSecretManagerAvailable = false;
let gcpTargetProjectId: string | null = null;
let gcpServiceAccountEmail: string | null = null;
let gcpCachedTokenPayload: { payload: StoredSecretPayload | null; cachedAt: number } | null = null;

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
// GOOGLE CLOUD RUN METADATA & SERVICE ACCOUNT IDENTITY ACCESS
// ============================================================================

export async function fetchMetadataServiceAccountAuth(): Promise<GcpServiceAccountAuth | null> {
  try {
    const headers = { 'Metadata-Flavor': 'Google' };
    const [projRes, tokRes, emailRes] = await Promise.all([
      fetch(`${METADATA_BASE}/project/project-id`, {
        headers,
        signal: AbortSignal.timeout(2_500),
      }),
      fetch(`${METADATA_BASE}/instance/service-accounts/default/token`, {
        headers,
        signal: AbortSignal.timeout(2_500),
      }),
      fetch(`${METADATA_BASE}/instance/service-accounts/default/email`, {
        headers,
        signal: AbortSignal.timeout(2_500),
      }).catch(() => null),
    ]);

    if (!tokRes.ok) return null;
    const tokJson: any = await tokRes.json().catch(() => null);
    const metaProj = projRes.ok ? (await projRes.text()).trim() : '';
    const projectId = (process.env.GCP_SECRET_MANAGER_PROJECT || process.env.GOOGLE_CLOUD_PROJECT || metaProj || '').trim();
    const serviceAccountEmail = emailRes && emailRes.ok ? (await emailRes.text()).trim() : 'Cloud Run Default Service Account';

    if (!tokJson?.access_token || !projectId) return null;
    gcpServiceAccountEmail = serviceAccountEmail;
    gcpTargetProjectId = projectId;

    return {
      accessToken: String(tokJson.access_token),
      projectId,
      serviceAccountEmail,
    };
  } catch {
    return null;
  }
}

export async function probeGcpSecretManager(force = false): Promise<boolean> {
  if (!force && gcpProbeDoneAt > 0 && Date.now() - gcpProbeDoneAt < 60_000) {
    return gcpSecretManagerAvailable;
  }
  gcpProbeDoneAt = Date.now();

  const auth = await fetchMetadataServiceAccountAuth();
  if (!auth) {
    gcpSecretManagerAvailable = false;
    return false;
  }

  try {
    const res = await fetch(
      `https://secretmanager.googleapis.com/v1/projects/${encodeURIComponent(auth.projectId)}/secrets?pageSize=1`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${auth.accessToken}` },
        signal: AbortSignal.timeout(3_500),
      }
    );

    if (res.ok) {
      gcpSecretManagerAvailable = true;
      gcpTargetProjectId = auth.projectId;
      gcpServiceAccountEmail = auth.serviceAccountEmail;
      return true;
    }

    gcpSecretManagerAvailable = false;
    return false;
  } catch {
    gcpSecretManagerAvailable = false;
    return false;
  }
}

// ============================================================================
// RETRIEVE OR PROVISION 256-BIT CRYPTOGRAPHIC KEY FROM SECRET MANAGER
// (Least Privilege: roles/secretmanager.secretAccessor on Cloud Run Identity)
// ============================================================================

export async function getOrCreateSecretManagerAesKey(forceFresh = false): Promise<Buffer> {
  if (!forceFresh && cachedSecretManagerAesKey && Date.now() - lastKeyFetchTime < GCP_CACHE_TTL_MS) {
    return cachedSecretManagerAesKey;
  }

  const auth = await fetchMetadataServiceAccountAuth();
  if (!auth) {
    throw new Error(
      'تعذر الوصول إلى Google Cloud Secret Manager لاسترجاع مفتاح التشفير الآمن (بيئة الخدمة غير متصلة بـ GCP Metadata Server). يرجى التأكد من تشغيل التطبيق في بيئة Cloud Run مع ربط حساب الخدمة بصلاحية Secret Manager Secret Accessor (roles/secretmanager.secretAccessor).'
    );
  }

  const parent = `projects/${encodeURIComponent(auth.projectId)}`;
  const secretName = `${parent}/secrets/${GCP_SECRET_MANAGER_AES_KEY_ID}`;
  const authHeaders = {
    Authorization: `Bearer ${auth.accessToken}`,
    'Content-Type': 'application/json',
  };

  // 1. Attempt to access latest version of the 256-bit AES key
  try {
    const accessRes = await fetch(
      `https://secretmanager.googleapis.com/v1/${secretName}/versions/latest:access`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${auth.accessToken}` },
        signal: AbortSignal.timeout(4_000),
      }
    );

    if (accessRes.ok) {
      const data: any = await accessRes.json().catch(() => null);
      const b64 = data?.payload?.data;
      if (b64) {
        const rawKeyStr = Buffer.from(String(b64), 'base64').toString('utf8').trim();
        let keyBuf: Buffer | null = null;
        if (rawKeyStr.length === 64 && /^[0-9a-fA-F]+$/.test(rawKeyStr)) {
          keyBuf = Buffer.from(rawKeyStr, 'hex');
        } else if (Buffer.from(String(b64), 'base64').length === 32) {
          keyBuf = Buffer.from(String(b64), 'base64');
        }
        if (keyBuf && keyBuf.length === 32) {
          cachedSecretManagerAesKey = keyBuf;
          lastKeyFetchTime = Date.now();
          return cachedSecretManagerAesKey;
        }
      }
    }

    if (accessRes.status === 403) {
      throw new Error(
        `تم رفض الوصول إلى Secret Manager (${secretName}): حساب خدمة Cloud Run (${auth.serviceAccountEmail}) يفتقر لصلاحية Secret Manager Secret Accessor (roles/secretmanager.secretAccessor). يرجى منح حساب الخدمة هذه الصلاحية في لوحة IAM & Admin.`
      );
    }

    if (accessRes.status === 404) {
      // 2. Secret does not exist yet. Generate cryptographically strong 256-bit random key
      const randomKeyBytes = crypto.randomBytes(32);
      const keyHex = randomKeyBytes.toString('hex');

      // Create secret in Secret Manager
      const createRes = await fetch(
        `https://secretmanager.googleapis.com/v1/${parent}/secrets?secretId=${GCP_SECRET_MANAGER_AES_KEY_ID}`,
        {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ replication: { automatic: {} } }),
          signal: AbortSignal.timeout(5_000),
        }
      );

      if (!createRes.ok && createRes.status !== 409) {
        throw new Error(
          `فشل إنشاء السر في Google Cloud Secret Manager (${createRes.status}): يرجى تفعيل Secret Manager API ومنح حساب خدمة Cloud Run (${auth.serviceAccountEmail}) الصلاحية المطلوبة.`
        );
      }

      // Add secret version with the 256-bit random key
      const b64Data = Buffer.from(keyHex, 'utf8').toString('base64');
      const addRes = await fetch(
        `https://secretmanager.googleapis.com/v1/${secretName}:addVersion`,
        {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ payload: { data: b64Data } }),
          signal: AbortSignal.timeout(5_000),
        }
      );

      if (!addRes.ok) {
        throw new Error(
          `فشل حفظ نسخة مفتاح التشفير الجديد في Google Cloud Secret Manager (${addRes.status}).`
        );
      }

      cachedSecretManagerAesKey = randomKeyBytes;
      lastKeyFetchTime = Date.now();
      return cachedSecretManagerAesKey;
    }

    throw new Error(
      `فشل استرجاع مفتاح التشفير من Secret Manager (HTTP ${accessRes.status}).`
    );
  } catch (err: any) {
    if (err.message && err.message.includes('Secret Manager')) {
      throw err;
    }
    throw new Error(
      `تعذر الوصول إلى Google Cloud Secret Manager لاسترجاع مفتاح التشفير: ${err?.message || String(err)}`
    );
  }
}

// ============================================================================
// AES-256-GCM ENCRYPTION & DECRYPTION (ZERO LOCAL CONTAINER FILE STORAGE)
// ============================================================================

export async function encryptTokenWithSecretManagerKey(token: string): Promise<EncryptedVaultRecord> {
  const key = await getOrCreateSecretManagerAesKey();
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

export async function decryptTokenWithSecretManagerKey(record: EncryptedVaultRecord): Promise<string | null> {
  if (!record || record.algorithm !== 'aes-256-gcm' || !record.iv || !record.tag || !record.data) {
    return null;
  }
  try {
    const key = await getOrCreateSecretManagerAesKey();
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

// Legacy fallback decryption strictly for seamless migration of existing records without data loss
function decryptLegacyMigrationToken(record: EncryptedVaultRecord): string | null {
  try {
    const legacySeed = 'e18d1b0ffead4e1873e86d6e01ae7314c865a4e415db8b744a739290ed5ddaef';
    const legacyKey = crypto.scryptSync(legacySeed, 'sami_app_vault_salt_2026_isolated_cloud_key', 32);
    const iv = Buffer.from(record.iv, 'hex');
    const tag = Buffer.from(record.tag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', legacyKey, iv);
    decipher.setAuthTag(tag);
    const decrypted = decipher.update(Buffer.from(record.data, 'hex'), undefined, 'utf8') + decipher.final('utf8');
    return decrypted.trim() || null;
  } catch {
    return null;
  }
}

// Clean up any historical container files so container remains 100% stateless
function purgeLocalContainerVaultFiles(): void {
  try {
    if (fs.existsSync(LEGACY_VAULT_FILE)) {
      fs.unlinkSync(LEGACY_VAULT_FILE);
    }
  } catch {}
  try {
    if (fs.existsSync(LEGACY_SEED_FILE)) {
      fs.unlinkSync(LEGACY_SEED_FILE);
    }
  } catch {}
}

// ============================================================================
// SECRET MANAGER TOKEN STORAGE & RETRIEVAL
// ============================================================================

async function readTokenFromSecretManager(bypassCache = false): Promise<StoredSecretPayload | null> {
  if (!bypassCache && gcpCachedTokenPayload && Date.now() - gcpCachedTokenPayload.cachedAt < GCP_CACHE_TTL_MS) {
    return gcpCachedTokenPayload.payload;
  }

  const auth = await fetchMetadataServiceAccountAuth();
  if (!auth) return null;

  try {
    const res = await fetch(
      `https://secretmanager.googleapis.com/v1/projects/${encodeURIComponent(auth.projectId)}/secrets/${GCP_SECRET_MANAGER_TOKEN_ID}/versions/latest:access`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${auth.accessToken}` },
        signal: AbortSignal.timeout(4_000),
      }
    );

    if (!res.ok) {
      gcpCachedTokenPayload = { payload: null, cachedAt: Date.now() };
      return null;
    }

    const data: any = await res.json().catch(() => null);
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
    gcpCachedTokenPayload = { payload: result, cachedAt: Date.now() };
    return result;
  } catch {
    return null;
  }
}

async function writeTokenToSecretManager(payload: StoredSecretPayload): Promise<boolean> {
  const auth = await fetchMetadataServiceAccountAuth();
  if (!auth) {
    throw new Error(
      'تعذر الاتصال بـ Google Cloud Secret Manager لحفظ التوكن (الخادم غير قادر على الوصول إلى GCP Metadata Server). يرجى التأكد من تشغيل الخدمة على Cloud Run.'
    );
  }

  const parent = `projects/${encodeURIComponent(auth.projectId)}`;
  const secretName = `${parent}/secrets/${GCP_SECRET_MANAGER_TOKEN_ID}`;
  const authHeaders = {
    Authorization: `Bearer ${auth.accessToken}`,
    'Content-Type': 'application/json',
  };

  try {
    const getSec = await fetch(`https://secretmanager.googleapis.com/v1/${secretName}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${auth.accessToken}` },
      signal: AbortSignal.timeout(4_000),
    });

    if (getSec.status === 404) {
      const createSec = await fetch(
        `https://secretmanager.googleapis.com/v1/${parent}/secrets?secretId=${GCP_SECRET_MANAGER_TOKEN_ID}`,
        {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ replication: { automatic: {} } }),
          signal: AbortSignal.timeout(5_000),
        }
      );
      if (!createSec.ok && createSec.status !== 409) {
        throw new Error(`فشل إنشاء سر التوكن في Secret Manager (HTTP ${createSec.status}).`);
      }
    } else if (getSec.status === 403) {
      throw new Error(
        `تم رفض إذن الكتابة في Secret Manager: حساب خدمة Cloud Run (${auth.serviceAccountEmail}) يفتقر لصلاحية Secret Manager Admin أو Secret Version Manager.`
      );
    } else if (!getSec.ok) {
      throw new Error(`فشل استعلام سر التوكن في Secret Manager (HTTP ${getSec.status}).`);
    }

    const b64Data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    const addVer = await fetch(`https://secretmanager.googleapis.com/v1/${secretName}:addVersion`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ payload: { data: b64Data } }),
      signal: AbortSignal.timeout(5_000),
    });

    if (!addVer.ok) {
      throw new Error(`فشل حفظ نسخة التوكن الجديدة في Secret Manager (HTTP ${addVer.status}).`);
    }

    gcpCachedTokenPayload = null;
    return true;
  } catch (err: any) {
    if (err.message && err.message.includes('Secret Manager')) throw err;
    throw new Error(`خطأ أثناء الكتابة في Secret Manager: ${err?.message || String(err)}`);
  }
}

// ============================================================================
// FIRESTORE ENCRYPTED BACKUP (Zero-Trust: Client access strictly denied in firestore.rules)
// ============================================================================

async function readFromFirestoreEncryptedRecord(): Promise<StoredSecretPayload | null> {
  if (!firestoreClient) return null;
  try {
    const doc = await firestoreClient.collection('server_secrets').doc('github_credentials').get();
    if (!doc.exists) return null;
    const record = doc.data() as EncryptedVaultRecord;

    // 1. Try decrypting with the new 256-bit Secret Manager key
    let decrypted = await decryptTokenWithSecretManagerKey(record).catch(() => null);

    // 2. If needed, attempt safe migration from legacy record
    if (!decrypted) {
      decrypted = decryptLegacyMigrationToken(record);
      if (decrypted) {
        // Automatically re-encrypt under the new Secret Manager key
        encryptTokenWithSecretManagerKey(decrypted)
          .then((newRec) => {
            firestoreClient.collection('server_secrets').doc('github_credentials').set(newRec, { merge: true }).catch(() => {});
          })
          .catch(() => {});
      }
    }

    if (!decrypted) return null;
    registerTokenForRedaction(decrypted);
    return { token: decrypted, updatedAt: record.updatedAt || Date.now() };
  } catch {
    return null;
  }
}

async function writeToFirestoreEncryptedRecord(token: string): Promise<boolean> {
  if (!firestoreClient) return false;
  try {
    const encrypted = await encryptTokenWithSecretManagerKey(token);
    await firestoreClient.collection('server_secrets').doc('github_credentials').set(encrypted, { merge: true });
    return true;
  } catch {
    return false;
  }
}

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
// MAIN RESOLUTION & VAULT STORAGE LOGIC
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

  // 1. In-memory runtime cache
  if (!forceFresh && activeVaultPayload?.token) {
    resolvedToken = activeVaultPayload.token;
    storageMode = secretManagerEnabled ? 'gcp_secret_manager' : 'server_env';
    updatedAt = activeVaultPayload.updatedAt;
  }

  // 2. Secret Manager payload
  if (!resolvedToken && secretManagerEnabled) {
    const smSecret = await readTokenFromSecretManager(forceFresh);
    if (smSecret?.token) {
      resolvedToken = smSecret.token;
      storageMode = 'gcp_secret_manager';
      updatedAt = smSecret.updatedAt;
      activeVaultPayload = smSecret;
    }
  }

  // 3. Firestore encrypted record (encrypted with 256-bit key from Secret Manager)
  if (!resolvedToken) {
    const fsVault = await readFromFirestoreEncryptedRecord();
    if (fsVault?.token) {
      resolvedToken = fsVault.token;
      storageMode = secretManagerEnabled ? 'gcp_secret_manager' : 'server_env';
      updatedAt = fsVault.updatedAt;
      activeVaultPayload = fsVault;
    }
  }

  // 4. Migrate any legacy file record if present, then purge file from container disk
  if (!resolvedToken && fs.existsSync(LEGACY_VAULT_FILE)) {
    try {
      const raw = fs.readFileSync(LEGACY_VAULT_FILE, 'utf8').trim();
      if (raw) {
        const rec = JSON.parse(raw) as EncryptedVaultRecord;
        const legacyDecrypted = decryptLegacyMigrationToken(rec);
        if (legacyDecrypted) {
          resolvedToken = legacyDecrypted;
          storageMode = secretManagerEnabled ? 'gcp_secret_manager' : 'server_env';
          updatedAt = rec.updatedAt || Date.now();
          activeVaultPayload = { token: resolvedToken, updatedAt };
          // Migrate into Firestore encrypted record
          writeToFirestoreEncryptedRecord(resolvedToken).catch(() => {});
          if (secretManagerEnabled) {
            writeTokenToSecretManager({ token: resolvedToken, updatedAt }).catch(() => {});
          }
        }
      }
    } catch {}
    purgeLocalContainerVaultFiles();
  }

  // 5. Permanent server environment secret fallback
  if (!resolvedToken && envCreds.token) {
    resolvedToken = envCreds.token;
    storageMode = 'server_env';
    activeVaultPayload = { token: resolvedToken, updatedAt: Date.now() };
  }

  if (resolvedToken) {
    registerTokenForRedaction(resolvedToken);
  }

  const resolvedOwner = cloudSettings.githubOwner || envCreds.owner || '';
  const resolvedRepo = cloudSettings.githubRepo || envCreds.repo || '';
  const hasSavedToken = resolvedToken.length > 0;
  const persistentVaultAvailable = secretManagerEnabled || envCreds.token.length > 0;

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
      tokenStatusAr: hasSavedToken ? 'التوكن محفوظ ومشفر في Google Cloud Secret Manager' : 'التوكن غير محفوظ',
      updatedAt,
      updatedBy: cloudSettings.updatedBy,
      apiServerUrl: cloudSettings.apiServerUrl,
      serviceAccountEmail: gcpServiceAccountEmail,
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
    // Retain existing verified token
  } else {
    registerTokenForRedaction(incomingToken);

    // REQUIREMENT 6: If Secret Manager is available or configured, save to Secret Manager
    const smAvailable = await probeGcpSecretManager(true);
    if (smAvailable) {
      await writeTokenToSecretManager({
        token: incomingToken,
        updatedAt: Date.now(),
      });
      await writeToFirestoreEncryptedRecord(incomingToken);
    } else {
      // Check if server environment token matches or if running in Cloud Run where Secret Manager must be accessed
      const envCreds = readPermanentEnvCredentials();
      const matchesEnv = envCreds.token.length > 0 && incomingToken === envCreds.token;
      if (!matchesEnv) {
        const auth = await fetchMetadataServiceAccountAuth();
        const saDesc = auth ? ` (${auth.serviceAccountEmail})` : '';
        throw new Error(
          `تعذر الوصول إلى Google Cloud Secret Manager لحفظ التوكن بشكل آمن. لحفظ توكن جديد، يرجى تفعيل Secret Manager API في مشروع Google Cloud ومنح حساب خدمة Cloud Run${saDesc} صلاحية Secret Manager Secret Accessor و Secret Version Manager (أو إضافة GITHUB_TOKEN في أسرار بيئة الخادم).`
        );
      }
    }

    // Update in-memory runtime cache (never saved to local container files)
    activeVaultPayload = {
      token: incomingToken,
      updatedAt: Date.now(),
    };
  }

  // Purge any legacy container files
  purgeLocalContainerVaultFiles();

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
    throw new Error('تعذر التحقق النهائي من حفظ إعدادات GitHub في الخادم السحابي');
  }

  return {
    owner: verified.owner,
    repo: verified.repo,
    hasToken: true,
    apiServerUrl: verified.apiServerUrl,
    vault: verified.vault,
  };
}
