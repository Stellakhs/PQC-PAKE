import hashlib
from typing import List
import time
import secrets
import math

Q = 12289
N = 256

# ============================
# 1. SEED & MATRIX GENERATION
# ============================

def gen_public_params(q: int, n : int): 
    assert q > 2 and all (q%p for p in range(2, int(q**(0.5)+1)))
    M = [[secrets.randbelow(q) for _ in range(n)] for _ in range(n)]
    return M

#print("M:",gen_public_params(Q,N))

'''
def derive_seed(password: str, purpose: str, length: int = 32) -> bytes:
    assert len(password) == 6 and password.isdigit(), "pw는 6자리 숫자 문자열로 가정"
    data = password.encode("utf-8") + b"|" + purpose.encode("ascii")
    return hashlib.sha3_256(data).digest()[:length]


def generate_matrix_from_password(password: str,
                                  n: int = N,
                                  q: int = Q) -> List[List[int]]:
    # M_pw := G(pw)  (pw로만 결정)
    seed = derive_seed(password, "matrix")
    total = n * n
    shake = hashlib.shake_128(seed)

    bytes_needed = total * 4
    stream = shake.digest(bytes_needed)

    coeffs = []
    pos = 0
    length = len(stream)

    while len(coeffs) < total and pos + 3 <= length:
        r0 = stream[pos]
        r1 = stream[pos + 1]
        r2 = stream[pos + 2]
        pos += 3

        t0 = r0 | ((r1 & 0x0F) << 8)
        t1 = (r1 >> 4) | (r2 << 4)

        if t0 < q:
            coeffs.append(t0)
        if len(coeffs) == total:
            break
        if t1 < q:
            coeffs.append(t1)

    if len(coeffs) < total:
        raise RuntimeError("lack of coefficient")

    M = [coeffs[i*n:(i+1)*n] for i in range(n)]
    return M
'''

# ============================
# 2. CBD SAMPLING (Noise)
# ============================

def sample_cbd_vector_from_seed(seed: bytes,
                                n: int = N,
                                eta: int = 2,
                                q: int = Q) -> List[int]:
    bits_per_coeff = 2 * eta
    bits_total = bits_per_coeff * n
    byte_len = (bits_total + 7) // 8

    stream = hashlib.shake_256(seed).digest(byte_len)

    buf = 0
    bits_in_buf = 0
    idx = 0

    def get_bits(k: int) -> int:
        nonlocal buf, bits_in_buf, idx
        while bits_in_buf < k:
            if idx >= len(stream):
                raise RuntimeError("SHAKE byte error")
            buf |= stream[idx] << bits_in_buf
            bits_in_buf += 8
            idx += 1
        val = buf & ((1 << k) - 1)
        buf >>= k
        bits_in_buf -= k
        return val

    coeffs: List[int] = []
    for _ in range(n):
        a_bits = get_bits(eta)
        c_bits = get_bits(eta)
        a = a_bits.bit_count()
        c = c_bits.bit_count()
        x = a - c
        coeffs.append(x % q)

    return coeffs


# --- CHANGED: s,e는 pw seed가 아니라 매번 CSPRNG로 fresh randomness ---
def sample_noise_vector_random(n: int = N,
                               eta: int = 2,
                               q: int = Q) -> List[int]:
    seed = secrets.token_bytes(32)
    return sample_cbd_vector_from_seed(seed, n=n, eta=eta, q=q)


# ============================
# 3. LINEAR ALGEBRA OPS
# ============================

def mat_vec_mul(M, v):
    rows = len(M)
    cols = len(M[0])
    result = [0] * rows

    for i in range(rows):
        total = 0
        for j in range(cols):
            total = total + (M[i][j] * v[j])
        result[i] = total % Q

    return result


def scalar_vec_mul(scalar, v):
    n = len(v)
    out = [0] * n
    for i in range(n):
        out[i] = (scalar * v[i]) % Q
    return out


def vec_add(a, b):
    n = len(a)
    out = [0] * n
    for i in range(n):
        out[i] = (a[i] + b[i]) % Q
    return out


def transpose(M):
    rows = len(M)
    cols = len(M[0])
    T = []
    for j in range(cols):
        new_row = []
        for i in range(rows):
            new_row.append(M[i][j])
        T.append(new_row)
    return T


# ============================
# 4. LWE MESSAGES
# ============================

def compute_p_A(M_pw, s_A, e_A):
    Ms = mat_vec_mul(M_pw, s_A)
    two_eA = scalar_vec_mul(2, e_A)
    p_A = vec_add(Ms, two_eA)
    return p_A


def compute_p_B(M_pw, s_B, e_B):
    M_T = transpose(M_pw)
    Mt_sB = mat_vec_mul(M_T, s_B)
    two_eB = scalar_vec_mul(2, e_B)
    p_B = vec_add(Mt_sB, two_eB)
    return p_B


# ============================
# 6. SIGNAL FUNCTIONS
# ============================

def center_lift(x):
    x = x % Q
    if x > Q // 2:
        x -= Q
    return x

def sigma0(x):
    xc = center_lift(x)
    bound = Q // 4
    if -bound <= xc <= bound:
        return 0
    return 1

def sigma1(x):
    xc = center_lift(x)
    bound = Q // 4
    if -(bound)+1 <= xc <= bound+1:
        return 0
    return 1

def hint_S(y):
    b = secrets.randbits(1)
    if b == 0:
        return sigma0(y)
    else:
        return sigma1(y)

def robust_extractor_E(x, sigma):
    assert sigma in (0, 1)
    half = (Q - 1) // 2
    val_mod_q = (x + sigma * half) % Q
    return val_mod_q % 2


# ============================
# 5. SHARED KEY VALUES
# ============================

# --- CHANGED: e'_A, e'_B는 "스칼라"로 샘플링해서 K에 2*e'를 더함 ---
def sample_noise_scalar_random(eta: int = 2) -> int:
    seed = secrets.token_bytes(32)
    x_mod_q = sample_cbd_vector_from_seed(seed, n=1, eta=eta, q=Q)[0]
    return center_lift(x_mod_q)  # 작은 signed 정수(예: -2..2)


def compute_K_B(p_A, s_B, e_B_prime_scalar: int):
    inner = 0
    for i in range(len(p_A)):
        inner = inner + (p_A[i] * s_B[i])
    K_B = (inner + 2 * e_B_prime_scalar) % Q
    return K_B


def compute_K_A(p_B, s_A, e_A_prime_scalar: int):
    inner = 0
    for i in range(len(p_B)):
        inner = inner + (s_A[i] * p_B[i])
    K_A = (inner + 2 * e_A_prime_scalar) % Q
    return K_A


# ============================
# 7. SINGLE RUN (PAKE)
# ============================

def run_pake():
    M = gen_public_params(Q, N)

    # --- CHANGED: s,e는 매 세션 랜덤 ---
    s_A = sample_noise_vector_random()
    e_A = sample_noise_vector_random()
    e_Ap = sample_noise_scalar_random()

    s_B = sample_noise_vector_random()
    e_B = sample_noise_vector_random()
    e_Bp = sample_noise_scalar_random()

    p_A = compute_p_A(M, s_A, e_A)
    p_B = compute_p_B(M, s_B, e_B)

    K_A = compute_K_A(p_B, s_A, e_Ap)
    K_B = compute_K_B(p_A, s_B, e_Bp)

    sigma = hint_S(K_B)

    SK_A = robust_extractor_E(K_A, sigma)
    SK_B = robust_extractor_E(K_B, sigma)

    return SK_A, SK_B, p_A, p_B, sigma


# ============================
# 8. NIST-STYLE MESSAGE SIZE
# ============================

def get_message_sizes():
    bits = math.ceil(math.log2(Q))  # 14 bits
    bytes_per_vector = (N * bits) // 8

    alice_to_bob = bytes_per_vector
    bob_to_alice = bytes_per_vector + 1  # sigma 1 byte(보고용 단순화)

    total = alice_to_bob + bob_to_alice
    return alice_to_bob, bob_to_alice, total


# ============================
# 9. NIST PERFORMANCE EXPERIMENT
# ============================

def performance_test(iterations=50):
    times = []
    failures = 0

    for _ in range(iterations):
        start = time.time()

        SK_A, SK_B, _, _, _ = run_pake()
        if SK_A != SK_B:
            failures += 1

        times.append(time.time() - start)

    avg = sum(times) / iterations
    std = (sum((t - avg) ** 2 for t in times) / iterations) ** 0.5
    fail_rate = failures / iterations

    return avg, std, fail_rate


# ============================
# 10. MAIN: PRINT NIST REPORT
# ============================

if __name__ == "__main__":

    print("\n===== Ding KE NIST-STYLE PERFORMANCE REPORT =====\n")

    m1, m2, total = get_message_sizes()
    print(f"Message size (Alice to Bob) : {m1} bytes")
    print(f"Message size (Bob to Alice) : {m2} bytes")
    print(f"Round-trip total           : {total} bytes\n")

    avg, std, fail = performance_test(50)
    print(f"Average execution time     : {avg*1000:.4f} ms")
    print(f"Std deviation              : {std*1000:.4f} ms")
    print(f"Reconciliation failure     : {fail*100:.2f}%")

    print("\n===================================================\n")
