import secrets

q = 12289 # 우선 수하 파라미터에 맞춰서 테스트 했어요

# signal function에서 Z_q 원소 x를 [-⌊q/2⌋, ⌊(q-1)/2⌋] 구간으로 옮길 때 필요
def center_lift(x):
    x = x % q
    if x > q // 2:
        x -= q
    return x

def sigma0(x):
    xc = center_lift(x)
    bound = q // 4 # ⌊q/4⌋
    if -bound <= xc <= bound:
        return 0
    return 1

def sigma1(x): 
    xc = center_lift(x)
    bound = q // 4
    if -(bound)+1 <= xc <= bound+1:
        return 0
    return 1

# Hint Algorithm S as: for any y in Z_q, S(y)=sigma_b(y), where b <-$-{0,1}
def hint_S(y):
    b = secrets.randbits(1)
    if b == 0:
        return sigma0(y)
    else: 
        return sigma1(y)
    

# Robust Extractor E
def robust_extractor_E(x, sigma):
    assert sigma in (0,1)
    assert q % 2 == 1 # (q-1)/2가 정수여야 함. 
    
    half = (q-1) // 2
    val_mod_q = (x + sigma * half) % q
    return val_mod_q % 2 # 최종 출력 k in {0,1}

#테스트용
K_A = 9216
K_B = 9218

# K_A = 250
# K_B = 246

sigma = hint_S(K_B)

SK_B = robust_extractor_E(K_B, sigma)

SK_A = robust_extractor_E(K_A, sigma)


print("sigma:", hint_S(K_B))
print("SK_B:", SK_B)
print("SK_A:", SK_A)