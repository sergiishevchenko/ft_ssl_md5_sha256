#include "whirlpool.h"
#include "ft_ssl.h"

extern const uint64_t	g_whirlpool_c0[256];
extern const uint64_t	g_whirlpool_rc[10];

// Build one output row of θ∘π∘γ (PDF §3.2–3.4; part of ρ in §3.7).
// Meaning: mix one row of the 8×8 state — substitute bytes, shift columns,
// diffuse across the row. σ[k] (XOR key) is done by the caller.
// Impl: T-tables §7.1 (not printed as C code in the PDF).
// Spec: https://www.karljapetre.com/whirlpool/whirlpool.pdf
// Tables: https://github.com/torvalds/linux/blob/master/crypto/wp512.c
static uint64_t	wp_round(const uint64_t *state, int row)
{
	uint64_t	result;
	uint64_t	c;
	int			t;
	uint8_t		idx;

	result = 0;
	t = 0;
	while (t < 8)
	{
		// §3.3 π — pick byte that lands in this row after column shift
		idx = (uint8_t)(state[(row - t + 8) % 8] >> (56 - t * 8));
		// §3.2 γ + §3.4 θ — S-box then MDS; packed as §7.1 T0[x]
		c = g_whirlpool_c0[idx];
		// §7.1 — column t uses rotate(T0), same as table Tt
		if (t > 0)
			c = (c >> (t * 8)) | (c << (64 - t * 8));
		result ^= c; // accumulate diffused bytes into this row
		t++;
	}
	return (result);
}

// §3.1 μ — map 64-byte block ↔ 8×8 byte matrix.
// Meaning: each dst[i] is one matrix row (8 bytes, big-endian).
static void	wp_load_block(uint64_t *dst, const uint8_t *block)
{
	int	i;

	i = 0;
	while (i < 8)
	{
		dst[i] = ((uint64_t)block[i * 8] << 56)
			| ((uint64_t)block[i * 8 + 1] << 48)
			| ((uint64_t)block[i * 8 + 2] << 40)
			| ((uint64_t)block[i * 8 + 3] << 32)
			| ((uint64_t)block[i * 8 + 4] << 24)
			| ((uint64_t)block[i * 8 + 5] << 16)
			| ((uint64_t)block[i * 8 + 6] << 8)
			| ((uint64_t)block[i * 8 + 7]);
		i++;
	}
}

// One compression step (§3.11): Hi = W[Hi-1](ηi) ⊕ Hi-1 ⊕ ηi
//   ctx->state = Hi-1 (chained hash / cipher key K)
//   block      = ηi   (message block)
//   W          = 10-round cipher (§3.9)
// Meaning: encrypt the block under the current hash, then fold
// ciphertext, old hash and block together (Miyaguchi–Preneel).
static void	whirlpool_transform(t_whirlpool_ctx *ctx, const uint8_t block[64])
{
	uint64_t	key[8]; 			// K^r — round key; starts as hash Hi-1
	uint64_t	data[8]; 			// cipher data; starts as message⊕key, ends as W(message)
	uint64_t	next_key[8]; 		// scratch for new key while key is still old
	uint64_t	next_data[8]; 		// scratch for new data while data is still old
	uint64_t	message_block[8]; 	// ηi — message block as 8 rows (fixed during rounds)
	int			row; 				// matrix row 0..7
	int			round; 				// round index 0..9

	wp_load_block(message_block, block); // ηi — plaintext block as matrix
	row = -1;
	while (++row < 8)
	{
		// §3.8 K^0 = K, and §3.11 sets K = Hi-1
		key[row] = ctx->state[row];
		// §3.9 first map of W: σ[K^0](ηi) = ηi ⊕ K^0
		data[row] = message_block[row] ^ key[row];
	}
	round = 0;
	while (round < 10) // §3.9 R = 10 rounds of ρ[K^r]
	{
		row = -1;
		while (++row < 8)
			// §3.8: K^r = ρ[c^r](K^{r-1}); here θ∘π∘γ before ⊕ c^r
			next_key[row] = wp_round(key, row);
		// §3.6 c^r only in row 0; §3.5 σ[c^r] finishes key round
		next_key[0] ^= g_whirlpool_rc[round];
		row = -1;
		while (++row < 8)
			key[row] = next_key[row];
		row = -1;
		while (++row < 8)
			// §3.7 ρ[K^r] = σ[K^r] ∘ θ ∘ π ∘ γ on data state
			next_data[row] = wp_round(data, row) ^ key[row];
		row = -1;
		while (++row < 8)
			data[row] = next_data[row];
		round++;
	}
	row = -1;
	while (++row < 8)
		// §3.11 Hi = W(ηi) ⊕ Hi-1 ⊕ ηi ; data = W(ηi) after 10 rounds
		//   ctx->state     = Hi-1 → Hi
		//   data           = W[Hi-1](ηi) after 10 rounds
		//   message_block  = ηi
		ctx->state[row] ^= data[row] ^ message_block[row];
}

// §3.11 / §3.12: H0 = IV = 512 zero bits.
void	whirlpool_init(void *ctx)
{
	t_whirlpool_ctx	*c;

	c = (t_whirlpool_ctx *)ctx;
	ft_memset(c, 0, sizeof(t_whirlpool_ctx));
}

// §3.12: feed bytes; every full 512-bit ηi → compress.
void	whirlpool_update(void *ctx, const uint8_t *data, size_t len)
{
	t_whirlpool_ctx	*c;
	size_t			i;

	c = (t_whirlpool_ctx *)ctx;
	i = 0;
	while (i < len)
	{
		c->buffer[c->buflen++] = data[i];
		if (c->buflen == 64)
		{
			whirlpool_transform(c, c->buffer);
			c->buflen = 0;
		}
		i++;
	}
	c->count += len;
}

// §3.10 padding: 1-bit, zeros to odd multiple of 256 bits, then 256-bit L.
// Meaning: mark end of message and append bit-length so identical
// prefixes of different lengths cannot collide.
// §3.12: digest = μ^{-1}(Ht) — state bytes, big-endian.
void	whirlpool_final(uint8_t *digest, void *ctx)
{
	t_whirlpool_ctx	*c;
	uint64_t		bits;
	int				i;

	c = (t_whirlpool_ctx *)ctx;
	bits = c->count * 8;
	c->buffer[c->buflen++] = 0x80;
	if (c->buflen > 32)
	{
		while (c->buflen < 64)
			c->buffer[c->buflen++] = 0x00;
		whirlpool_transform(c, c->buffer);
		c->buflen = 0;
	}
	while (c->buflen < 32)
		c->buffer[c->buflen++] = 0x00;
	ft_memset(c->buffer + 32, 0, 24);
	i = 7;
	while (i >= 0)
	{
		c->buffer[56 + (7 - i)] = (uint8_t)(bits >> (i * 8));
		i--;
	}
	whirlpool_transform(c, c->buffer);
	i = 0;
	while (i < 8)
	{
		digest[i * 8] = (uint8_t)(c->state[i] >> 56);
		digest[i * 8 + 1] = (uint8_t)(c->state[i] >> 48);
		digest[i * 8 + 2] = (uint8_t)(c->state[i] >> 40);
		digest[i * 8 + 3] = (uint8_t)(c->state[i] >> 32);
		digest[i * 8 + 4] = (uint8_t)(c->state[i] >> 24);
		digest[i * 8 + 5] = (uint8_t)(c->state[i] >> 16);
		digest[i * 8 + 6] = (uint8_t)(c->state[i] >> 8);
		digest[i * 8 + 7] = (uint8_t)(c->state[i]);
		i++;
	}
}
