import os, hashlib
from typing import Tuple

# ─── Параметры Kyber-512 ──────────────────────────────────────────
K    = 2
N    = 256
Q    = 3329
ETA1 = 3
ETA2 = 2
DU   = 10
DV   = 4

# ─── Zetas: 17^(bitrev7(k)) mod Q  для k=0..127 ─────────────────
def _bitrev7(n):
    r=0
    for _ in range(7): r=(r<<1)|(n&1); n>>=1
    return r

ZETAS = [pow(17, _bitrev7(k), Q) for k in range(128)]

# ─── Арифметика полиномов ─────────────────────────────────────────
def poly_add(a,b): return [(x+y)%Q for x,y in zip(a,b)]
def poly_sub(a,b): return [(x-y)%Q for x,y in zip(a,b)]

def ntt(f):
    """Kyber NTT (in-place, bit-reversed order)"""
    f=list(f); k=1; length=128
    while length>=2:
        start=0
        while start<256:
            zeta=ZETAS[k]; k+=1
            for j in range(start, start+length):
                t=zeta*f[j+length]%Q
                f[j+length]=(f[j]-t)%Q
                f[j]=(f[j]+t)%Q
            start+=2*length
        length>>=1
    return f

def intt(f):
    f=list(f); k=127; length=2
    while length<=128:
        start=0
        while start<256:
            zeta=ZETAS[k]; k-=1
            for j in range(start, start+length):
                t=f[j]
                f[j]=(t+f[j+length])%Q
                f[j+length]=zeta*(f[j+length]-t)%Q
            start+=2*length
        length<<=1
    inv=pow(128,Q-2,Q)
    return [c*inv%Q for c in f]

def basemul(a0,a1,b0,b1,z):
    return (a0*b0+z*a1*b1)%Q, (a0*b1+a1*b0)%Q

def poly_mul_ntt(a,b):
    c=[0]*256; k=64
    for i in range(0,256,4):
        zeta=ZETAS[k]; k+=1
        c[i],c[i+1]   =basemul(a[i],a[i+1],  b[i],b[i+1],   zeta)
        c[i+2],c[i+3] =basemul(a[i+2],a[i+3],b[i+2],b[i+3],-zeta)
    return c

def vec_dot(av,bv):
    acc=[0]*256
    for a,b in zip(av,bv): acc=poly_add(acc,poly_mul_ntt(a,b))
    return acc

def mat_vec(M,v): return [vec_dot(row,v) for row in M]

# ─── Hash / PRF / XOF ────────────────────────────────────────────
def H(b):    return hashlib.sha3_256(b).digest()
def G(b):    h=hashlib.sha3_512(b).digest(); return h[:32],h[32:]
def PRF(s,b,n): sh=hashlib.shake_256(); sh.update(s+bytes([b])); return sh.digest(n)
def XOF(rho,i,j,n): sh=hashlib.shake_128(); sh.update(rho+bytes([i,j])); return sh.digest(n)

# ─── Sampling ─────────────────────────────────────────────────────
def sample_ntt(seed):
    coeffs=[]; buf=bytearray(); pos=0
    buf+=seed
    while len(coeffs)<256:
        if pos+3>len(buf):
            sh=hashlib.shake_128(); sh.update(seed); buf=bytearray(sh.digest(len(buf)+64))
        d1=buf[pos]|((buf[pos+1]&0xF)<<8)
        d2=(buf[pos+1]>>4)|(buf[pos+2]<<4)
        pos+=3
        if d1<Q: coeffs.append(d1)
        if d2<Q and len(coeffs)<256: coeffs.append(d2)
    return coeffs[:256]

def cbd(b,eta):
    bits=[]
    for byte in b:
        for i in range(8): bits.append((byte>>i)&1)
    poly=[]
    for i in range(256):
        a=sum(bits[2*eta*i+j] for j in range(eta))
        bb=sum(bits[2*eta*i+eta+j] for j in range(eta))
        poly.append((a-bb)%Q)
    return poly

def gen_A(rho):
    return [[sample_ntt(XOF(rho,i,j,672)) for j in range(K)] for i in range(K)]

# ─── Encode / Decode ──────────────────────────────────────────────
def encode(poly,l):
    bits=[]
    for c in poly:
        for i in range(l): bits.append((c>>i)&1)
    return bytes(sum(bits[i*8+j]<<j for j in range(8) if i*8+j<len(bits)) for i in range(len(bits)//8))

def decode(b,l):
    bits=[]
    for byte in b:
        for i in range(8): bits.append((byte>>i)&1)
    return [sum(bits[i*l+j]<<j for j in range(l)) for i in range(256)]

def encode_vec(vec,l): return b''.join(encode(p,l) for p in vec)
def decode_vec(b,l):
    n=256*l//8; return [decode(b[i*n:(i+1)*n],l) for i in range(K)]

# ─── Compress / Decompress ───────────────────────────────────────
def compress(x,d):   return round(x*(1<<d)/Q)%(1<<d)
def decompress(x,d): return round(x*Q/(1<<d))%Q
def cpoly(p,d): return [compress(c,d) for c in p]
def dpoly(p,d): return [decompress(c,d) for c in p]

_PB12  = 256*12//8   # 384
PK_LEN = _PB12*K+32  # 800

# ─── KEM ──────────────────────────────────────────────────────────
def keygen():
    d=os.urandom(32); rho,sigma=G(d)
    A=gen_A(rho)
    s=[cbd(PRF(sigma,i,  64*ETA1),ETA1) for i in range(K)]
    e=[cbd(PRF(sigma,K+i,64*ETA1),ETA1) for i in range(K)]
    s_hat=[ntt(si) for si in s]
    e_hat=[ntt(ei) for ei in e]
    t_hat=[poly_add(mat_vec(A,s_hat)[i],e_hat[i]) for i in range(K)]
    pk=encode_vec(t_hat,12)+rho
    sk=encode_vec(s_hat,12)+pk+H(pk)+os.urandom(32)
    return pk,sk

def encapsulate(pk):
    t_hat=decode_vec(pk[:_PB12*K],12); rho=pk[_PB12*K:]
    A=gen_A(rho)
    m=os.urandom(32); mh=H(m)
    K_bar,r=G(mh+H(pk))
    r_vec=[cbd(PRF(r,i,  64*ETA1),ETA1) for i in range(K)]
    e1   =[cbd(PRF(r,K+i,64*ETA2),ETA2) for i in range(K)]
    e2   = cbd(PRF(r,2*K,64*ETA2),ETA2)
    r_hat=[ntt(ri) for ri in r_vec]
    AT=[[A[j][i] for j in range(K)] for i in range(K)]
    u=[poly_add(intt(vec_dot(AT[i],r_hat)),e1[i]) for i in range(K)]
    # encode m as 1-bit polynomial
    m_poly=[round(((mh[i//8]>>(i%8))&1)*Q/2)%Q for i in range(256)]
    v=poly_add(poly_add(intt(vec_dot(t_hat,r_hat)),e2),m_poly)
    ct=encode_vec([cpoly(ui,DU) for ui in u],DU)+encode(cpoly(v,DV),DV)
    return ct,K_bar

def decapsulate(sk,ct):
    s_hat=decode_vec(sk[:_PB12*K],12)
    pk=sk[_PB12*K:_PB12*K+PK_LEN]
    pb_du=256*DU//8; pb_dv=256*DV//8
    u=[dpoly(p,DU) for p in decode_vec(ct[:pb_du*K],DU)]
    v=dpoly(decode(ct[pb_du*K:pb_du*K+pb_dv],DV),DV)
    su=intt(vec_dot(s_hat,[ntt(ui) for ui in u]))
    m_poly=poly_sub(v,su)
    m_bytes=bytes(sum(compress(m_poly[i*8+j],1)<<j for j in range(8)) for i in range(32))
    K_bar,_=G(m_bytes+H(pk))
    return K_bar

# ─── Kyber-CPA: прямое шифрование данных ─────────────────────────
# Математическая основа: Module-LWE (диофантовы уравнения)
# Шифрует произвольные данные блоками по 32 байта без AES

_BLOCK    = 32                           # байт открытого текста на блок
_CT_BLOCK = K * 256*DU//8 + 256*DV//8  # байт шифртекста на блок (768)

def kyber_cpa_encrypt_block(pk: bytes, msg32: bytes) -> bytes:
    """Шифрует ровно 32 байта через Kyber-CPA (IND-CPA secure)."""
    assert len(msg32) == 32
    t_hat  = decode_vec(pk[:_PB12*K], 12)
    rho    = pk[_PB12*K:]
    A      = gen_A(rho)
    r_seed = os.urandom(32)
    r_vec  = [cbd(PRF(r_seed, i,   64*ETA1), ETA1) for i in range(K)]
    e1     = [cbd(PRF(r_seed, K+i, 64*ETA2), ETA2) for i in range(K)]
    e2     =  cbd(PRF(r_seed, 2*K, 64*ETA2), ETA2)
    r_hat  = [ntt(ri) for ri in r_vec]
    AT     = [[A[j][i] for j in range(K)] for i in range(K)]
    u = [poly_add(intt(vec_dot(AT[i], r_hat)), e1[i]) for i in range(K)]
    m_poly = [round(((msg32[i//8] >> (i%8)) & 1) * Q / 2) % Q for i in range(256)]
    v = poly_add(poly_add(intt(vec_dot(t_hat, r_hat)), e2), m_poly)
    return encode_vec([cpoly(ui, DU) for ui in u], DU) + encode(cpoly(v, DV), DV)

def kyber_cpa_decrypt_block(sk: bytes, ct: bytes) -> bytes:
    """Расшифровывает один блок (768 байт) -> 32 байта."""
    s_hat = decode_vec(sk[:_PB12*K], 12)
    pb_du = 256*DU//8; pb_dv = 256*DV//8
    u = [dpoly(p, DU) for p in decode_vec(ct[:pb_du*K], DU)]
    v = dpoly(decode(ct[pb_du*K:pb_du*K+pb_dv], DV), DV)
    su = intt(vec_dot(s_hat, [ntt(ui) for ui in u]))
    m_poly = poly_sub(v, su)
    return bytes(sum(compress(m_poly[i*8+j], 1) << j for j in range(8)) for i in range(32))

def kyber_encrypt(pk: bytes, data: bytes) -> bytes:
    """Шифрует произвольные данные через Kyber-CPA (PKCS7 паддинг)."""
    pad = _BLOCK - (len(data) % _BLOCK)
    padded = data + bytes([pad] * pad)
    result = b''
    for i in range(0, len(padded), _BLOCK):
        result += kyber_cpa_encrypt_block(pk, padded[i:i+_BLOCK])
    return result

def kyber_decrypt(sk: bytes, ct: bytes) -> bytes:
    """Расшифровывает данные, зашифрованные kyber_encrypt."""
    result = b''
    for i in range(0, len(ct), _CT_BLOCK):
        result += kyber_cpa_decrypt_block(sk, ct[i:i+_CT_BLOCK])
    return result[:-result[-1]]  # убираем PKCS7 паддинг
