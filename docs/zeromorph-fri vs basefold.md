## zeromorph-fri vs basefold
### zeromorph-fri

分析文档：[zeromorph-fri-analysis](../../zeromorph/zeromorph-fri/analysis/zeromorph-fri-analysis.md)

Prover's Cost:

$$
\begin{align}
 & (2\mathcal{R}\cdot nN + (2\mathcal{R} \log \mathcal{R} + \frac{17}{2} \mathcal{R} + 3) \cdot  N + 2 \cdot n -  \mathcal{R}\log \mathcal{R} - 7\mathcal{R} - 4) ~\mathbb{F}_{\mathsf{mul}} + (\frac{7}{2} \mathcal{R} \cdot N - 3 \mathcal{R} + 1) ~\mathbb{F}_{\mathsf{inv}} \\
& + \mathsf{MMCS.commit}(2^{n-1} \cdot \mathcal{R}, \ldots, \mathcal{R}) + \sum_{i = 1}^{n - 1}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) + \sum_{i = 1}^{n - 2}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R})
\end{align}
$$

Proof size:

$$
((4l + 1)n - 2l + 3) ~ \mathbb{F} + \left(2l \cdot N + (4\log \mathcal{R} \cdot l - 3 l + 1) n - 4 \log \mathcal{R} \cdot l - l\right) ~H
$$

Verifier's Cost:

$$
\begin{aligned}
  & (l \cdot N + (2 l\log \mathcal{R} - l)n - 2l \log \mathcal{R} - l) ~ C + \left( l \cdot N + (2l\log \mathcal{R} - l) n - 2l \log \mathcal{R} + 5l \right) ~ H\\
  & + ((11l + 5)n + 3l + 1) ~ \mathbb{F}_{\mathsf{mul}} + (5ln + l) ~ \mathbb{F}_{\mathsf{inv}}
\end{aligned}
$$

### basefold

分析文档：[basefold-analysis](../../FRI/BaseFold/analysis/basefold-analysis.md)

Prover's cost:

$$
\begin{aligned}
\left((\frac{5}{2} \mathcal{R} + 9) \cdot N + 3d - \frac{5}{2} \mathcal{R} - 13 \right) ~ \mathbb{F}_{\mathsf{mul}} + (\mathcal{R} \cdot N - \mathcal{R}) ~ \mathbb{F}_{\mathsf{inv}} + \sum_{i = 1}^{d - 1} \mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) 
\end{aligned}
$$

若加上 Prover 计算编码 $\pi_d$ 的算法复杂度，则总复杂度为

$$
\left(\frac{\mathcal{R}}{2} \cdot dN + (\frac{5}{2} \mathcal{R} + 9) \cdot N + 3d - \frac{5}{2} \mathcal{R} - 13 \right) ~ \mathbb{F}_{\mathsf{mul}} + (\mathcal{R} \cdot N - \mathcal{R}) ~ \mathbb{F}_{\mathsf{inv}} + \sum_{i = 1}^{d - 1} \mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) 
$$

Proof size:

$$
((2l + 3)d + \mathcal{R}) ~ \mathbb{F} + \left( \frac{l}{2} \cdot N + \left(\log \mathcal{R} \cdot l +\frac{1}{2} \cdot l + 1\right) \cdot d \right) ~ H 
$$

Verifier's cost:

$$
\left( \frac{l}{2} \cdot N + (l\log \mathcal{R} + \frac{l}{2})d \right)  ~ H + (5l + 12)d ~ \mathbb{F}_{\mathsf{mul}} + ((2l + 5)d + 1) ~ \mathbb{F}_{\mathsf{inv}}
$$

### Compare

#### Prover Cost

将 zeromorph-fri Prover cost 减去 basefold 加上编码复杂度的 Prover cost，结果为

$$
\begin{align}
& (2\mathcal{R}\cdot nN + (2\mathcal{R} \log \mathcal{R} + \frac{17}{2} \mathcal{R} + 3) \cdot  N + 2 \cdot n -  \mathcal{R}\log \mathcal{R} - 7\mathcal{R} - 4) ~\mathbb{F}_{\mathsf{mul}} + (\frac{7}{2} \mathcal{R} \cdot N - 3 \mathcal{R} + 1) ~\mathbb{F}_{\mathsf{inv}} \\
& + \mathsf{MMCS.commit}(2^{n-1} \cdot \mathcal{R}, \ldots, \mathcal{R}) + \sum_{i = 1}^{n - 1}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) + \sum_{i = 1}^{n - 2}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) \\
 & - \left(\left(\frac{\mathcal{R}}{2} \cdot dN + (\frac{5}{2} \mathcal{R} + 9) \cdot N + 3d - \frac{5}{2} \mathcal{R} - 13 \right) ~ \mathbb{F}_{\mathsf{mul}} + (\mathcal{R} \cdot N - \mathcal{R}) ~ \mathbb{F}_{\mathsf{inv}} + \sum_{i = 1}^{d - 1} \mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) \right) \\
=  & ( \frac{3}{2}\mathcal{R}\cdot nN + (2\mathcal{R} \log \mathcal{R} + \frac{12}{2} \mathcal{R} - 6) \cdot  N - \cdot n -  \mathcal{R}\log \mathcal{R} - \frac{9}{2}\mathcal{R} + 9) ~\mathbb{F}_{\mathsf{mul}} + (\frac{5}{2} \mathcal{R} \cdot N - 3 \mathcal{R} + 1) ~\mathbb{F}_{\mathsf{inv}} \\
& + \mathsf{MMCS.commit}(2^{n-1} \cdot \mathcal{R}, \ldots, \mathcal{R}) + \sum_{i = 1}^{n - 2}\mathsf{MT.commit}(2^{i} \cdot \mathcal{R}) \\
\end{align}
$$
可以看出 basefold 远比 zeromorph-fri 计算量小，体现在有限域的乘法计算，求逆操作还是进行 Merkle Tree 承诺的哈希计算上。

若 basefold 不算上编码的复杂度，则 zeromorph-fri 的计算复杂度是 $O(nN)$ ，而 basefold 的复杂度是 $O(n)$ 的。

- 有限域乘法：zeromorph-fri 产生 $2 \mathcal{R} \cdot nN$ 的有限域乘法，主要复杂度来自于计算 $\{[\hat{q}_k(x)|_{x \in D^{(k)}}]\}_{k = 0}^{n - 1}$ 以及 $[f(x)|_{x \in D}]$ ，会涉及 FFT 的运算，而 basefold 中只有在编码过程中有 $\frac{\mathcal{R}}{2} \cdot dN ~ \mathbb{F}_{\mathsf{mul}}$ 的计算复杂度。
- 哈希计算：zeromorph-fri 调用了两次 FRI 的子协议，而 basefold 只调用了一次，自然 zeromorph-fri 要进行的 Hash 计算增加。

#### Proof size

将 zeromorph-fri proof Size 减去 basefold 的 proof size，结果为

$$
\begin{align}
 & ((4l + 1)n - 2l + 3) ~ \mathbb{F} + \left(2l \cdot N + (4\log \mathcal{R} \cdot l - 3 l + 1) n - 4 \log \mathcal{R} \cdot l - l\right) ~H \\
 & - \left(((2l + 3)d + \mathcal{R}) ~ \mathbb{F} + \left( \frac{l}{2} \cdot N + \left(\log \mathcal{R} \cdot l +\frac{1}{2} \cdot l + 1\right) \cdot d \right) ~ H  \right) \\
=  & ((2l - 2)n - 2l - \mathcal{R}+ 3) ~ \mathbb{F} + \left(\frac{3}{2}l \cdot N + (3\log \mathcal{R} \cdot l - \frac{7}{2} l) n - 4 \log \mathcal{R} \cdot l - l\right) ~H
\end{align}
$$
basefold 在 proof size 上优于 zeromorph-fri。

-  zeromorph-fri 调用了两次 FRI 的子协议，而 basefold 只调用了一次，自然 zeromorph-fri 要发送的 proof size 就会增多。

#### Verifier Cost

将 zeromorph-fri verifier cost 减去 basefold 的 verifier cost，结果为

$$
\begin{align} \\
& (l \cdot N + (2 l\log \mathcal{R} - l)n - 2l \log \mathcal{R} - l) ~ C + \left( l \cdot N + (2l\log \mathcal{R} - l) n - 2l \log \mathcal{R} + 5l \right) ~ H\\
  & + ((11l + 5)n + 3l + 1) ~ \mathbb{F}_{\mathsf{mul}} + (5ln + l) ~ \mathbb{F}_{\mathsf{inv}} \\
 & - \left(\left( \frac{l}{2} \cdot N + (l\log \mathcal{R} + \frac{l}{2})d \right)  ~ H + (5l + 12)d ~ \mathbb{F}_{\mathsf{mul}} + ((2l + 5)d + 1) ~ \mathbb{F}_{\mathsf{inv}}\right) \\
=  & (l \cdot N + (2 l\log \mathcal{R} - l)n - 2l \log \mathcal{R} - l) ~ C + \left( \frac{1}{2}l \cdot N + (l\log \mathcal{R} - \frac{3}{2}l) n - 2l \log \mathcal{R} + 5l \right) ~ H\\
  & + ((6l - 7)n + 3l + 1) ~ \mathbb{F}_{\mathsf{mul}} + ((3l - 5)n + l - 1) ~ \mathbb{F}_{\mathsf{inv}} \\
\end{align}
$$

basefold 在 verifier cost 上优于 zeromorph-fri。

- verifier cost ，主要也是由于 zeromorph-fri 调用 FRI 协议次数更多导致的。

#### 总结

综合来看，basefold 协议都要远远优于 zeromorph-fri 协议。