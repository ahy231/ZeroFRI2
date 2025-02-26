## zeromorph-fri vs basefold
### zeromorph-fri

分析文档：[zeromorph-fri-analysis](/docs/zeromorph-fri-analysis.md)

Prover's Cost:

$$
\begin{aligned}
  & (\frac{4}{3}\mathcal{R} N^2 + (6 \mathcal{R} + 5) N + n - \frac{22}{3} \mathcal{R} - 6)  ~ \mathbb{F}_{\mathsf{mul}} + (2\mathcal{R}N - 2\mathcal{R} + 2) ~ \mathbb{F}_{\mathsf{inv}} \\
  & + \mathsf{MMCS.commit}(2^{n-1} \cdot \mathcal{R}, \ldots, \mathcal{R}) + \sum_{i = 1}^{n - 1}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) + \\
  & + \sum_{i = 1}^{n - 2}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) \\
\end{aligned}
$$

Proof size:

$$
((4l + 1)n - 2l + 3) ~ \mathbb{F} + \left(2l \cdot n^2 + (4\log \mathcal{R} \cdot l - 3 l + 1) n - 4 \log \mathcal{R} \cdot l - l\right) ~H
$$

Verifier's Cost:

$$
\begin{aligned}
  & (ln^2 + (2 l\log \mathcal{R} - l)n - 2l \log \mathcal{R} - l) ~ C + \left( ln^2 + (2l\log \mathcal{R} - l) n - 2l \log \mathcal{R} + 5l \right) ~ H\\
  & + (N + (9l + 3)n - l - 1) ~ \mathbb{F}_{\mathsf{mul}} + (5ln + l) ~ \mathbb{F}_{\mathsf{inv}}
\end{aligned}
$$

### basefold

分析文档：[basefold-analysis](/docs/basefold-analysis.md)

Prover's cost:

$$
\left((\frac{5}{2} \mathcal{R} + 10) \cdot N - \frac{5}{2} \mathcal{R} - 14 \right) ~ \mathbb{F}_{\mathsf{mul}} + (\mathcal{R} \cdot N - \mathcal{R}) ~ \mathbb{F}_{\mathsf{inv}} + \sum_{i = 1}^{d - 1} \mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) 
$$

Proof size:

$$
((2l + 3)d + \mathcal{R}) ~ \mathbb{F} + \left( \frac{l}{2} \cdot d^2 + \left(\frac{1}{2} \cdot l + \log \mathcal{R} \cdot l + 1\right) \cdot d \right) ~ H 
$$

Verifier's cost:

$$
\left( \frac{l}{2} \cdot d^2 + (l\log \mathcal{R} + \frac{l}{2})d \right)  ~ H + (3 N+ (5l + 9)d - 2) ~ \mathbb{F}_{\mathsf{mul}} + ((2l + 5)d + 1) ~ \mathbb{F}_{\mathsf{inv}}
$$

### Compare

结论： basefold 协议除了在 verifier 的有限域乘法计算上比 zeromorph-fri 协议多了大约 $2N$ 外，其余方面都要优于 zeromorph-fri 协议，包括 prover 的计算，proof size，verifier 中的有限域求逆和哈希计算。

Prover's Cost:

- 有限域的乘法，zeromorph-fri 协议是 $O(N^2)$ 的，而 basefold 是 $O(N)$ ，basefold 明显优于 zeromorph-fri 协议。

	zeromorph-fri 协议中引入了 $N^2$ 项，来源于在 zeromorph-fri 协议的 Round 2 中， 对于 $0 \le k < n$ ，Prover 计算
	
	$$
	q_{\hat{q}_k}(X) = \frac{\hat{q_k}(X) - \hat{q}_k(\zeta)}{X - \zeta}
	$$
	
	在 $D^{(k)}$ 上的值。在这一步中计算 $[q_{\hat{q}_k}(x)|_{x \in D^{(k)}}]$ 是 $O(N^2)$ 的。

- 有限域的除法，zeromorph-fri 协议会比 basefold 协议多 $(\mathcal{R} \cdot N - \mathcal{R} + 2) ~ \mathbb{F}_{\mathsf{inv}}$ ，basefold 协议优于 zeromorph-fri 协议。

	主要原因是在 zeromorph-fri 协议中会进行两次 FRI 的 low degree test ，一个是 $q_{f_\zeta}(X)$ ，另一个是将 $n$ 个商多项式 $q_{\hat{q}_k}(X)$ 放在一起进行 low degree test ，在 low degree test 中，进行折叠计算时会涉及有限域的求逆操作，而 basefold 协议全程只进行一次 low degree test，因此 zeromorph-fri 协议中的求逆操作会多 $O(N)$ 个。
- Merkle Tree 承诺，可以看到 basefold 优于 zeromorph-fri。
	
	原因是 zeromorph-fri 协议中需要承诺的多项式远比 basefold 多，zeromorph-fri 协议中还要处理 $n$ 个商多项式 $\hat{q}_k(X)$ 。

综合上面分析的三个方面，basefold 在 prover 计算上明显优于 zeromorph-fri 协议。

Proof size:

- 有限域的大小，zeromorph-fri 协议比 basefold 协议多出 $((2l - 2)n - 2l + 3 - \mathcal{R}) ~ \mathbb{F}$ 。主要是 zeromorph-fri 协议中进行的 low degree test 的比 basefold 多，那么需要发送的有限域中的值也就变多了。
- 哈希值，basefold 协议优于 zeromorph-fri 协议，zeromorph-fri 协议要比 basefold 协议多发送的哈希值有
$$
\left(\frac{3l}{2}\cdot n^2 + (3\log \mathcal{R} \cdot l - \frac{7}{2} l) n - 4 \log \mathcal{R} \cdot l - l\right) ~H
$$
	主要原因也是 zeromorph-fri 协议中进行 low degree test 的次数更多，导致了需要发送的哈希值变多。

在 proof size 方面，basefold 优于 zeromorph-fri 。

Verifier's Cost:

- 有限域乘法，basefold 协议比 zeromorph-fri 协议要多计算 $(2 N+ (6 - 4l)d - 2 + l + 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。这里主要是 basefold 协议 verifier 需要自己计算 $\tilde{eq}((\alpha_0,\ldots,\alpha_{d-1}), \mathbf{u})$ ，引入了 $3N$ 的有限域乘法。zeromorph-fri 协议中是为了计算 $\Phi_{n - k}(\zeta^{2^k})(0 \le k < n)$ 时，计算 $\zeta$ 的幂次，引入了 $N$ 级的有限域乘法，因此最终 basefold 协议的有限域乘法比 zeromorph-fri 协议多。
- 有限域求逆，basefold 优于 zeromorph-fri 协议，zeromorph-fri 协议比 basefold 协议多计算 $((3l - 5)n + l - 1) ~ \mathbb{F}_{\mathsf{inv}}$ 。主要原因在于 zeromorph-fri 协议验证的 low degree test 次数更多，折叠过程中会引入求逆计算。
- 哈希计算或压缩算法计算，basefold 优于 zeromorph-fri 协议，原因自然也是 zeromorph-fri 协议发送的 Merkle Tree 承诺更多，Verifier 验证时的计算就自然增加了。

综合来看，在 verifier's cost 方面，basefold 协议比 zeromorph-fri 协议多了大约 $2N$ 的有限域乘法计算，但是在有限域求逆和哈希计算上都优于 zeromorph-fri 协议。

## English Version

### zeromorph-fri

Analysis document: [zeromorph-fri-analysis](/docs/zeromorph-fri-analysis.md)
Prover's Cost:

$$
\begin{aligned}
	& (\frac{4}{3}\mathcal{R} N^2 + (6 \mathcal{R} + 5) N + n - \frac{22}{3} \mathcal{R} - 6)  ~ \mathbb{F}_{\mathsf{mul}} + (2\mathcal{R}N - 2\mathcal{R} + 2) ~ \mathbb{F}_{\mathsf{inv}} \\
	& + \mathsf{MMCS.commit}(2^{n-1} \cdot \mathcal{R}, \ldots, \mathcal{R}) + \sum_{i = 1}^{n - 1}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) + \\
	& + \sum_{i = 1}^{n - 2}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) \\
\end{aligned}
$$

Proof size:

$$
((4l + 1)n - 2l + 3) ~ \mathbb{F} + \left(2l \cdot n^2 + (4\log \mathcal{R} \cdot l - 3 l + 1) n - 4 \log \mathcal{R} \cdot l - l\right) ~H
$$

Verifier's Cost:

$$
\begin{aligned}
	& (ln^2 + (2 l\log \mathcal{R} - l)n - 2l \log \mathcal{R} - l) ~ C + \left( ln^2 + (2l\log \mathcal{R} - l) n - 2l \log \mathcal{R} + 5l \right) ~ H\\
	& + (N + (9l + 3)n - l - 1) ~ \mathbb{F}_{\mathsf{mul}} + (5ln + l) ~ \mathbb{F}_{\mathsf{inv}}
\end{aligned}
$$

### basefold

Analysis document: [basefold-analysis](/docs/basefold-analysis.md)

Prover's cost:

$$
\left((\frac{5}{2} \mathcal{R} + 10) \cdot N - \frac{5}{2} \mathcal{R} - 14 \right) ~ \mathbb{F}_{\mathsf{mul}} + (\mathcal{R} \cdot N - \mathcal{R}) ~ \mathbb{F}_{\mathsf{inv}} + \sum_{i = 1}^{d - 1} \mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) 
$$

Proof size:

$$
((2l + 3)d + \mathcal{R}) ~ \mathbb{F} + \left( \frac{l}{2} \cdot d^2 + \left(\frac{1}{2} \cdot l + \log \mathcal{R} \cdot l + 1\right) \cdot d \right) ~ H 
$$

Verifier's cost:

$$
\left( \frac{l}{2} \cdot d^2 + (l\log \mathcal{R} + \frac{l}{2})d \right)  ~ H + (3 N+ (5l + 9)d - 2) ~ \mathbb{F}_{\mathsf{mul}} + ((2l + 5)d + 1) ~ \mathbb{F}_{\mathsf{inv}}
$$

### Compare

Conclusion: The basefold protocol is superior to the zeromorph-fri protocol in all aspects except for the verifier's finite field multiplication, where it is approximately $2N$ more than the zeromorph-fri protocol.

Prover's Cost:

- Finite field multiplication: The zeromorph-fri protocol is $O(N^2)$, while basefold is $O(N)$, making basefold significantly better than zeromorph-fri.

	In the zeromorph-fri protocol, the $N^2$ term is introduced in Round 2, where for $0 \le k < n$, the Prover computes
	
	$$
	q_{\hat{q}_k}(X) = \frac{\hat{q_k}(X) - \hat{q}_k(\zeta)}{X - \zeta}
	$$
	
	on $D^{(k)}$. Calculating $[q_{\hat{q}_k}(x)|_{x \in D^{(k)}}]$ in this step is $O(N^2)$.

- Finite field division: The zeromorph-fri protocol has $(\mathcal{R} \cdot N - \mathcal{R} + 2) ~ \mathbb{F}_{\mathsf{inv}}$ more than the basefold protocol, making basefold superior.

	The main reason is that the zeromorph-fri protocol performs two FRI low degree tests: one for $q_{f_\zeta}(X)$ and another for the $n$ quotient polynomials $q_{\hat{q}_k}(X)$ together. The low degree test involves finite field inversion, whereas the basefold protocol performs only one low degree test, resulting in $O(N)$ fewer inversions in the zeromorph-fri protocol.
- Merkle Tree commitments: Basefold is better than zeromorph-fri.

	The zeromorph-fri protocol requires more polynomial commitments than basefold, including handling $n$ quotient polynomials $\hat{q}_k(X)$.

In summary, basefold is significantly better than zeromorph-fri in prover computation.

Proof size:

- Finite field size: The zeromorph-fri protocol has $((2l - 2)n - 2l + 3 - \mathcal{R}) ~ \mathbb{F}$ more than basefold. This is mainly because the zeromorph-fri protocol performs more low degree tests, requiring more finite field values to be sent.
- Hash values: Basefold is better than zeromorph-fri. The zeromorph-fri protocol sends more hash values:
$$
\left(\frac{3l}{2}\cdot n^2 + (3\log \mathcal{R} \cdot l - \frac{7}{2} l) n - 4 \log \mathcal{R} \cdot l - l\right) ~H
$$
	The main reason is the additional low degree tests in the zeromorph-fri protocol, resulting in more hash values to be sent.

In terms of proof size, basefold is better than zeromorph-fri.

Verifier's Cost:

- Finite field multiplication: The basefold protocol has $(2 N+ (6 - 4l)d - 2 + l + 1) ~ \mathbb{F}_{\mathsf{mul}}$ more than zeromorph-fri. This is mainly because the basefold verifier needs to compute $\tilde{eq}((\alpha_0,\ldots,\alpha_{d-1}), \mathbf{u})$, introducing $3N$ finite field multiplications. In the zeromorph-fri protocol, finite field multiplications are introduced when computing $\Phi_{n - k}(\zeta^{2^k})(0 \le k < n)$, resulting in $N$ finite field multiplications. Thus, the basefold protocol has more finite field multiplications than zeromorph-fri.
- Finite field inversion: Basefold is better than zeromorph-fri. The zeromorph-fri protocol has $((3l - 5)n + l - 1) ~ \mathbb{F}_{\mathsf{inv}}$ more than basefold. The main reason is the additional low degree tests in the zeromorph-fri protocol, introducing more inversions.
- Hash computation or compression algorithm: Basefold is better than zeromorph-fri. The zeromorph-fri protocol requires more Merkle Tree commitments, increasing the verifier's computation.

In summary, in terms of verifier's cost, the basefold protocol has approximately $2N$ more finite field multiplications than the zeromorph-fri protocol, but is better in finite field inversion and hash computation.
