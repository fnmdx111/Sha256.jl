module Sha256
export digest

#######################################################################

# Helper functions
ch(x::Uint32, y::Uint32, z::Uint32) = (x & y) $ (~x & z)
maj(x::Uint32, y::Uint32, z::Uint32) = (x & y) $ (x & z) $ (y & z)
rot(x::Uint32, n) = x >>> n | x << (32 - n)
shift(x::Uint32, n) = x >>> n
sigma0(x::Uint32) = rot(x, 2) $ rot(x, 13) $ rot(x, 22)
sigma1(x::Uint32) = rot(x, 6) $ rot(x, 11) $ rot(x, 25)
sgm0(x::Uint32) = rot(x, 7) $ rot(x, 18) $ shift(x, 3)
sgm1(x::Uint32) = rot(x, 17) $ rot(x, 19) $ shift(x, 10)

#######################################################################

#######################################################################

# S-box
const k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
           0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
           0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
           0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
           0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
           0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
           0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
           0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

#######################################################################

#######################################################################

# Message expansion
# msg is an array of Uint32
function expand_msg(msg)
    w = Array(Uint32, 64)
    w[1:16] = msg

    for j = 17:64
        w[j] = sgm1(w[j - 2]) + w[j - 7] + sgm0(w[j - 15]) + w[j - 16]
    end

    return w
end

#######################################################################

#######################################################################

# Message padding
# msg is an array of Uint8, representing the original message in bytes
function pad(msg)
    function construct(slc)
        local _::Uint32 = 0
        for i in [int(i) for i in slc]
            _ <<= 8
            _ |= i
        end
        return _
    end

    function to_byte_array(number)
        reverse(reinterpret(Uint8, [number]))
    end

    len, = size(msg)
    l = len * 8
    k = mod(448 - 1 - l, 512)
    k_byte = div(k + 1, 8) - 1
    msg = vcat(msg, [0x80], zeros(k_byte), to_byte_array(l))

    len, = size(msg)
    n = div(len * 8, 512)

    const rounds::Int32 = 64 / 4

    ret = zeros(Uint32, rounds * n)
    for i = 1:n
        for j = 1:rounds
            ret[16(i - 1)+ j] = construct(msg[64(i - 1) + 4(j - 1) + 1:64(i - 1) + 4j])
        end
    end
    return ret, n
end

#######################################################################

#######################################################################
# Compression
# init is an array of Uint32 (the initial hash values)
# w is an array of Uint32 (the expanded message)
function compress(init, w)
    a, b, c, d, e, f, g, h = init

    for j = 1:64
        t1::Uint32 = h + sigma1(e) + ch(e, f, g) + k[j] + w[j]
        t2::Uint32 = sigma0(a) + maj(a, b, c)
        h = g
        g = f
        f = e
        e::Uint32 = d + t1
        d = c
        c = b
        b = a
        a::Uint32 = t1 + t2
    end
    init[1] += a
    init[2] += b
    init[3] += c
    init[4] += d
    init[5] += e
    init[6] += f
    init[7] += g
    init[8] += h

    return init
end

#######################################################################

#######################################################################
# Message digestion
# msg is an array of Uint8, representing the original message in bytes
function digest(msg)
    blocks, n = pad(msg)
    m = [0x6a09e667, 0xbb67ae85,
         0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c,
         0x1f83d9ab, 0x5be0cd19]
    init = copy(m)
    for i = 1:n
        w = expand_msg(blocks[16(i - 1) + 1:16i])
        compress(m, w)
    end

    return m
end

#######################################################################

end # module

