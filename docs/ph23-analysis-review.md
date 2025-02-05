# 协议性能分析

## PH23+KZG10 协议（优化版）

对于 KZG10 协议，因为其 Commitment 具有加法同态性。

### Precomputation 

1. 预计算 $s_0(X),\ldots, s_{n-1}(X)$ and $v_H(X)$	


$$
v_H(X) = X^N -1 
$$
$$
s_i(X) = \frac{v_H(X)}{v_{H_i}(X)} = \frac{X^N-1}{X^{2^i}-1}
$$

2. 预计算 $D=(1, \omega, \omega^2, \ldots, \omega^{2^{n-1}})$ 上的 Bary-Centric Weights $\{\hat{w}_i\}$。这个可以加速 


$$
\hat{w}_j = \prod_{l\neq j} \frac{1}{\omega^{2^j} - \omega^{2^l}}
$$


3. 预计算 Lagrange Basis 的 KZG10 SRS $A_0 =[L_0(\tau)]_1, A_1= [L_1(\tau)]_1, A_2=[L_2(\tau)]_1, \ldots, A_{N-1} = [L_{2^{n-1}}(\tau)]_1$ 


### Common inputs

1. $C_a=[\hat{f}(\tau)]_1$:  the (uni-variate) commitment of $\tilde{f}(X_0, X_1, \ldots, X_{n-1})$ 
2. $\vec{u}=(u_0, u_1, \ldots, u_{n-1})$: 求值点
3. $v=\tilde{f}(u_0,u_1,\ldots, u_{n-1})$: MLE 多项式 $\tilde{f}$ 在 $\vec{X}=\vec{u}$ 处的运算值


### Commit 计算过程

1. Prover 构造一元多项式 $a(X)$，使其 Evaluation form 等于 $\vec{a}=(a_0, a_1, \ldots, a_{N-1})$，其中 $a_i = \tilde{f}(\mathsf{bits}(i))$, 为 $\tilde{f}$ 在 Boolean Hypercube $\{0,1\}^n$ 上的取值。

$$
a(X) = a_0\cdot L_0(X) + a_1\cdot L_1(X) + a_2\cdot L_2(X)
+ \cdots + a_{N-1}\cdot L_{N-1}(X)
$$

> Prover: 使用 FFT 计算多项式 $a(X)$ 的系数，计算复杂度是 $N\log N ~\mathbb{F}_{\mathsf{mul}}$ 。 

2. Prover 计算 $\hat{f}(X)$ 的承诺 $C_a$，并发送 $C_a$

$$
C_{a} = a_0\cdot A_0 + a_1\cdot A_1 + a_2\cdot A_2 + \cdots + a_{N-1}\cdot A_{N-1} = [\hat{f}(\tau)]_1
$$

其中 $A_0 =[L_0(\tau)]_1, A_1= [L_1(\tau)]_1, A_2=[L_2(\tau)]_1, \ldots, A_{N-1} = [L_{2^{n-1}}(\tau)]_1$ ，在预计算过程中已经得到。

> Prover: 算法复杂度为 $\mathsf{msm}(N, \mathbb{G}_1)$ ，表示 $N$ 长的向量的承诺。

> #### Commit 阶段复杂度
>
> 在 commit 阶段 prover 的复杂度总计为：
>
> $$
> N\log N ~\mathbb{F}_{\mathsf{mul}} + \mathsf{msm}(N, \mathbb{G}_1)
> $$

### Evaluation 证明协议

回忆下证明的多项式运算的约束：

$$
\tilde{f}(u_0, u_1, u_2, \ldots, u_{n-1}) = v
$$

这里 $\vec{u}=(u_0, u_1, u_2, \ldots, u_{n-1})$ 是一个公开的挑战点。

#### Round 1.

Prover:

1. 计算向量 $\vec{c}$，其中每个元素 $c_i=\overset{\sim}{eq}(\mathsf{bits}(i), \vec{u})$

> Prover: 
> 
> 向量 $\vec{c}$ 的计算算法为
> 
> ```python
> @classmethod
> def eqs_over_hypercube(cls, rs):
>     k = len(rs)
>     n = 1 << k
>     evals = [Field(1)] * n
>     half = 1
>     for i in range(k):
>         for j in range(half):
>             evals[j+half] = evals[j] * rs[i]
>             evals[j] = evals[j] - evals[j+half]
>         half *= 2
>     return evals
> ```
> 例如 $k = 2$ ，计算结果应该为
> 
> $$
> \begin{aligned}
>   00 & \quad (1 - u_0) & (1- u_1)  \\
>   10 & \quad u_0 & (1- u_1) \\
>   01 & \quad (1 - u_0) & u_1 \\
>   11 & \quad u_0 & u_1
> \end{aligned}
> $$
> 
> 这个算法就是先按 $u_0$ 所在的二进制位进行计算，接着如果增加一位 $u_1$ ，再更新所有的元素。
> 
> - `for j in range(1)` 循环内部计算出 `evals[1]` 和 `evals[0]`:
>   - `evals[1]` = $u_0$ ，对应 $u_0$ 所在的位 `1`
>   - `evals[0]` = $1 - u_0$ ，对应 $u_0$ 所在的二进制位 `0`
> - `for j in range(2)` ，更新 $u_1$ 所在的位。
>   - `j = 0`，更新 `evals[0]` 和 `evals[2]`
>   - `j = 1`，更新 `evals[1]` 和 `evals[3]`
> 
> 每次循环 `for j in range(half)` 内部有 1 次有限域上的乘法，即 `evals[j+half] = evals[j] * rs[i]` ，而 `half` 的变化为 $1, 2, 2^2, \ldots, 2^{k-1}$ ，因此总共的有限域乘法个数为：
> 
> $$
>   1 + 2 + 2^2 + \ldots + 2^{k - 1} = \frac{1(1 - 2^k)}{1 - 2} = 2^k - 1 = N - 1
> $$
> 
> 因此这里的计算复杂度为 $(N - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。

2. 构造多项式 $c(X)$，其在 $H$ 上的运算结果恰好是 $\vec{c}$ 。

$$
c(X) = \sum_{i=0}^{N-1} c_i \cdot L_i(X)
$$
 > Prover: 使用 FFT 算法，通过 $\vec{c}$ 来构造 $c(X)$ ，复杂度为 $N \log N ~ \mathbb{F}_{\mathsf{mul}}$ 。

3. 计算 $c(X)$ 的承诺 $C_c= [c(\tau)]_1$，并发送 $C_c$

$$
C_c = \mathsf{KZG10.Commit}(\vec{c})  =  [c(\tau)]_1 
$$

>Prover: 这里算法复杂度为  $\mathsf{msm}(N, \mathbb{G}_1)$

> #### Round 1 复杂度
> 
> Prover 复杂度为：
>
> $$
> (N - 1) ~ \mathbb{F}_{\mathsf{mul}} + N \log N ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{msm}(N, \mathbb{G}_1)
> $$

#### Round 2.

Verifier: 发送挑战数 $\alpha\leftarrow_{\$}\mathbb{F}_p$ 

Prover: 

1. 构造关于 $\vec{c}$ 的约束多项式 $p_0(X),\ldots, p_{n}(X)$

$$
\begin{split}
p_0(X) &= s_0(X) \cdot \Big( c(X) - (1-u_0)(1-u_1)...(1-u_{n-1}) \Big) \\
p_k(X) &= s_{k-1}(X) \cdot \Big( u_{n-k}\cdot c(X) - (1-u_{n-k})\cdot c(\omega^{2^{n-k}}\cdot X)\Big) , \quad k=1\ldots n
\end{split}
$$
> Prover: 
> - $s_0(X), \ldots, s_n(X)$ 已经在预计算过程中得到了，根据公式
> $$
>  s_i(X) = \frac{X^N - 1}{X^{2^i} - 1}
> $$
> 得到 $\deg(s_i) = N - 2^i$
> 
> #### 计算 $p_0(X)$ 
> 
> - $(1-u_0)(1-u_1)...(1-u_{n-1})$ 已经计算过了，为 $\vec{c}[0]$ ，将其作为常数多项式，然后进行多项式的减法，$c(X) - \vec{c}[0]$ ，这里涉及的是两个多项式的系数相加减，不涉及有限域的乘法，这里不进行计入。
> - 用上一步得到的多项式与 $s_0(X)$ 进行相乘，由于 $\deg(c) = N - 1$ ，这里多项式相乘的复杂度记为 $\mathsf{polymul}(N - 1,N - 1)$ ，表示次数为 $N - 1$ 与次数为 $N - 1$ 的多项式相乘的复杂度。
>
> 因此，计算 $p_0(X)$ 的算法复杂度为 $\mathsf{polymul}(N - 1,N - 1)$ .
> 
> #### 计算 $p_k(X)$
> 
> 先分析计算 $c(\omega^{2^{n-k}}\cdot X)$ 的复杂度，这里 $(\omega^0, \omega^2, \omega^4, \ldots, \omega^{2^{n-1}})$ 都可以预先计算得出。$c(X)$ 已经计算得到，假设其为
> 
> $$
> c(X) = c'_0 + c'_1 X + \ldots + c'_{N - 1} X^{N-1}
> $$
> 
> 因此
> 
> $$
> c(\omega^i \cdot X) = c'_0 + c'_1 \cdot \omega^i \cdot X + \ldots + c'_{N-1} \cdot (\omega^i)^{N-1} \cdot X^{N-1}
> $$
> 
> $c(\omega^i \cdot X)$ 多项式的系数可以通过上面这种方式得到，直接对 $c(X)$ 的系数进行对应计算即可，除了常数项没有有限域乘法外，这里有 $N - 1$ 次有限域的乘法操作，同理计算 $c(\omega^{2^{n-k}}\cdot X)$ 复杂度也是 $(N - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。
>
> - 计算 $(1-u_{n-k})\cdot c(\omega^{2^{n-k}}\cdot X)$ 复杂度就为两个多项式相乘的复杂度，即 $\mathsf{polymul}(0, N - 1)$
>
> - 计算 $u_{n-k}\cdot c(X)$ 复杂度：$\mathsf{polymul}(0, N - 1)$
> - 计算 $s_{k-1}(X) \cdot \Big( u_{n-k}\cdot c(X) - (1-u_{n-k})\cdot c(\omega^{2^{n-k}}\cdot X)\Big)$ 复杂度也就是两个多项式相乘的复杂度: $\mathsf{polymul}(N - 2^{k - 1}, N - 1)$
> 
> 综合上述分析，计算 $p_k(X)$ 的复杂度为：$(N - 1) ~ \mathbb{F}_{\mathsf{mul}} + 2~\mathsf{polymul}(0, N - 1) + \mathsf{polymul}(N - 2^{k - 1}, N - 1)$
>
> #### 复杂度
>
> 将上面分析得到的复杂度相加
> $$
>   \begin{aligned}
>     & \mathsf{polymul}(N - 1,N - 1) + \sum_{k = 1}^{n} \big((N - 1) ~ \mathbb{F}_{\mathsf{mul}} + 2~\mathsf{polymul}(0, N - 1) + \mathsf{polymul}(N - 2^{k - 1}, N - 1) \big) \\
>     & = n(N - 1) ~ \mathbb{F}_{\mathsf{mul}} + 2n~\mathsf{polymul}(0, N - 1) + \mathsf{polymul}(N - 1,N - 1) + \sum_{k = 1}^{n} \mathsf{polymul}(N - 2^{k - 1}, N - 1)
>  \end{aligned}
> $$


2. 把 $\{p_i(X)\}$ 聚合为一个多项式 $p(X)$ 

$$
p(X) = p_0(X) + \alpha\cdot p_1(X) + \alpha^2\cdot p_2(X) + \cdots + \alpha^{n}\cdot p_{n}(X)
$$

> Prover:
> 
> - 由 $\alpha$ 计算得到 $\alpha^2, \alpha^3, \ldots, \alpha^n$ ，总共有 $n - 1$ 次有限域上的乘法，因此复杂度是 $(n - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。
> - 这里每个 $\alpha^i$ 构成一个常数多项式，再与 $p_i(X)$ 相乘，且 
> 
> $$
> \deg(p_i) = N - 2^{i - 1} + N - 1 = 2N - 2^{i - 1} - 1, \quad i = 1, \ldots, n
> $$
> 
> 最后这些多项式再相加，因此计算 $p(X)$ 的总共复杂度为
> 
> $$
> (n - 1) ~ \mathbb{F}_{\mathsf{mul}} + \sum_{k = 1}^{n} \mathsf{polymul}(0, 2N - 2^{k - 1} - 1)
> $$

3. 构造累加多项式 $z(X)$，满足

$$
\begin{split}
z(1) &= a_0\cdot c_0 \\
z(\omega_{i}) - z(\omega_{i-1}) &=  a(\omega_{i})\cdot c(\omega_{i}), \quad i=1,\ldots, N-1 \\ 
z(\omega^{N-1}) &= v \\
\end{split}
$$

> - 计算 $a(\omega_{i})\cdot c(\omega_{i})$ 会涉及一次有限域的乘法操作，总共有 $N ~ \mathbb{F}_{\mathsf{mul}}$ 
> - 计算得到 $\vec{z}$ 之后会用 FFT 得到 $z(X)$ ，复杂度为 $N \log N ~ \mathbb{F}_{\mathsf{mul}}$
>
> 因此总复杂度为： 
> $$
>   N ~ \mathbb{F}_{\mathsf{mul}} + N \log N ~ \mathbb{F}_{\mathsf{mul}}
> $$

4. 构造约束多项式 $h_0(X), h_1(X), h_2(X)$，满足

$$
\begin{split}
h_0(X) &= L_0(X)\cdot\big(z(X) - c_0\cdot a(X) \big) \\
h_1(X) &= (X-1)\cdot\big(z(X)-z(\omega^{-1}\cdot X)-a(X)\cdot c(X)) \\
h_2(X) & = L_{N-1}(X)\cdot\big( z(X) - v \big) \\
\end{split}
$$

> 计算 $h_0(X)$， $L_0(X)$ 可以预先计算得到
> - $c_0\cdot a(X)$ 复杂度为: $\mathsf{polymul}(0, N - 1)$
> - $L_0(X)\cdot\big(z(X) - c_0\cdot a(X) \big)$ 复杂度：$\mathsf{polymul}(N - 1, N - 1)$
> 
> 因此计算 $h_0(X)$ 的总复杂度为 $\mathsf{polymul}(0, N - 1) + \mathsf{polymul}(N - 1, N - 1)$
> 
> 计算 $h_1(X)$
> - $z(\omega^{-1}\cdot X)$ : $(N - 1) ~ \mathbb{F}_{\mathsf{mul}}$
> - $a(X)\cdot c(X)$ : $\mathsf{polymul}(N - 1, N - 1)$
> - $(X-1)\cdot\big(z(X)-z(\omega^{-1}\cdot X)-a(X)\cdot c(X))$ :  $\mathsf{polymul}(1, 2N - 2)$
> 
> 因此计算 $h_1(X)$ 的总复杂度为 $(N - 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(N - 1, N - 1) + \mathsf{polymul}(1, 2N - 2)$
> 
> 计算 $h_2(X)$ 
> - $L_{N-1}(X)$ 可以提前计算得到
> - $L_{N-1}(X)\cdot\big( z(X) - v \big)$： $\mathsf{polymul}(N - 1, N - 1)$
> 
> 因此，在这一步的总计算复杂度为：
> 
> $$
> (N - 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - 1) + 3~\mathsf{polymul}(N - 1, N - 1)  + \mathsf{polymul}(1, 2N - 2)
> $$

5. 把 $p(X)$ 和 $h_0(X), h_1(X), h_2(X)$ 聚合为一个多项式 $h(X)$，满足

$$
\begin{split}
h(X) &= p(X) + \alpha^{n+1} \cdot h_0(X) + \alpha^{n+2} \cdot h_1(X) + \alpha^{n+3} \cdot h_2(X)
\end{split}
$$

> 在这一轮中的前面第 2 步已经计算出 $\alpha^2, \ldots, \alpha^n$ ，现在要计算 $\alpha^{n + 1}, \alpha^{n + 3} , \alpha^{n + 3}$ ，这里涉及 $3$ 次有限域上的乘法，因此复杂度为 $3 ~ \mathbb{F}_{\mathsf{mul}}$ 。
> 
> 分析多项式的乘法
> 
> - $\deg(h_0) = 2N - 2$ ，计算 $\alpha^{n+1} \cdot h_0(X)$ 复杂度为 $\mathsf{polymul}(0, 2N - 2)$
> - $\deg(h_1) = 1 + 2N - 2 = 2N - 1$ ，计算 $\alpha^{n+2} \cdot h_1(X)$ 复杂度为 $\mathsf{polymul}(0, 2N - 1)$
> - $\deg(h_2) = 2N - 2$ ，计算 $\alpha^{n+3} \cdot h_2(X)$ 复杂度为 $\mathsf{polymul}(0, 2N - 2)$
> 因此多项式乘法的复杂度为：
> $$
>   2~\mathsf{polymul}(0, 2N - 2) + \mathsf{polymul}(0, 2N - 1)
> $$
>
> 综合下来，这一步总的复杂度为：
>
> $$
> 3 ~ \mathbb{F}_{\mathsf{mul}} + 2~\mathsf{polymul}(0, 2N - 2) + \mathsf{polymul}(0, 2N - 1)
> $$

6. 计算 Quotient 多项式 $t(X)$，满足

$$
h(X) =t(X)\cdot v_H(X)
$$

> 这一步涉及多项式的除法，分析多项式的次数 $\deg(h) = 2N - 1$ ，$\deg(v_H) = N$ ，因此记这里多项式除法的复杂度为 $\mathsf{polydiv}(2N - 1, N)$ 。

7. 计算 $C_t=[t(\tau)]_1$， $C_z=[z(\tau)]_1$，并发送 $C_t$ 和 $C_z$

$$
\begin{split}
C_t &= \mathsf{KZG10.Commit}(t(X)) = [t(\tau)]_1 \\
C_z &= \mathsf{KZG10.Commit}(z(X)) = [z(\tau)]_1
\end{split}
$$

> 这一步是两个多项式承诺
> - $C_t$: 由于 $\deg(t) = N - 1$ ，因此复杂度为 $\mathsf{msm}(N, \mathbb{G}_1)$
> - $C_z$: $\mathsf{msm}(N, \mathbb{G}_1)$
> 总计： 
> $$
> 2 ~ \mathsf{msm}(N, \mathbb{G}_1)
> $$


> #### Round 2 复杂度
> 
> Prover 复杂度为：
> 
> $$
> \begin{aligned}
>   & \mathsf{term_1}:  n(N - 1) ~ \mathbb{F}_{\mathsf{mul}} + 2n~\mathsf{polymul}(0, N - 1) + \mathsf{polymul}(N - 1,N - 1) + \sum_{k = 1}^{n} \mathsf{polymul}(N - 2^{k - 1}, N - 1) \\
>   & \mathsf{term_2}: (n - 1) \mathbb{F}_{\mathsf{mul}} + \sum_{k = 1}^{n} \mathsf{polymul}(0, 2N - 2^{k - 1} - 1) \\
>   & \mathsf{term_3}: N ~ \mathbb{F}_{\mathsf{mul}} + N \log N ~ \mathbb{F}_{\mathsf{mul}} \\
>   & \mathsf{term_4}: (N - 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - 1) + 3~\mathsf{polymul}(N - 1, N - 1)  + \mathsf{polymul}(1, 2N - 2) \\
>   & \mathsf{term_5}: 3~\mathbb{F}_{\mathsf{mul}} + 2~\mathsf{polymul}(0, 2N - 2) + \mathsf{polymul}(0, 2N - 1) \\
>   & \mathsf{term_6}: \mathsf{polydiv}(2N - 1, N) \\
>   & \mathsf{term_7}: 2 ~ \mathsf{msm}(N, \mathbb{G}_1)
> \end{aligned}
> $$
> 
> 总计为：
>
> $$
> \begin{aligned}
>   & (n(N - 1) + (n - 1) + N + N \log N + (N - 1) + 3) ~ \mathbb{F}_{\mathsf{mul}}  \\
>   & + (2n + 1) ~ \mathsf{polymul}(0, N - 1) + \mathsf{polymul}(0, 2N - 1) + 2~\mathsf{polymul}(0, 2N - 2) +  \mathsf{polymul}(1, 2N - 2)  \\
>   & + 4 ~ \mathsf{polymul}(N - 1, N - 1)+ \sum_{k = 1}^{n} \mathsf{polymul}(N - 2^{k - 1}, N - 1) + \sum_{k = 1}^{n} \mathsf{polymul}(0, 2N - 2^{k - 1} - 1) \\
>   & + \mathsf{polydiv}(2N - 1, N) \\
>   & + 2 ~ \mathsf{msm}(N, \mathbb{G}_1) \\
>   = & ((n + 2)N + N \log N + 2) ~ \mathbb{F}_{\mathsf{mul}}  \\
>   & + (2n + 1) ~ \mathsf{polymul}(0, N - 1) + \mathsf{polymul}(0, 2N - 1) + 2~\mathsf{polymul}(0, 2N - 2) +  \mathsf{polymul}(1, 2N - 2)  \\
>   & + 4 ~ \mathsf{polymul}(N - 1, N - 1)+ \sum_{k = 1}^{n} \mathsf{polymul}(N - 2^{k - 1}, N - 1) + \sum_{k = 1}^{n} \mathsf{polymul}(0, 2N - 2^{k - 1} - 1) \\
>   & + \mathsf{polydiv}(2N - 1, N) \\
>   & + 2 ~ \mathsf{msm}(N, \mathbb{G}_1) \\
> \end{aligned}
> $$


#### Round 3.

Verifier: 发送随机求值点 $\zeta\leftarrow_{\$}\mathbb{F}_p$ 

Prover: 

1. 计算 $s_i(X)$ 在 $\zeta$ 处的取值：

$$
s_0(\zeta), s_1(\zeta), \ldots, s_{n-1}(\zeta)
$$

这里 Prover 可以高效计算 $s_i(\zeta)$ ，由 $s_i(X)$ 的公式得

$$
\begin{aligned}
  s_i(\zeta) & = \frac{\zeta^N - 1}{\zeta^{2^i} - 1} \\
  & = \frac{(\zeta^N - 1)(\zeta^{2^i} +1)}{(\zeta^{2^i} - 1)(\zeta^{2^i} +1)} \\
  & = \frac{\zeta^N - 1}{\zeta^{2^{i + 1}} - 1} \cdot (\zeta^{2^i} +1) \\
  & = s_{i + 1}(\zeta) \cdot (\zeta^{2^i} +1)
\end{aligned} 
$$

因此 $s_i(\zeta)$ 的值可以通过 $s_{i + 1}(\zeta)$ 计算得到，而

$$
s_{n-1}(\zeta) = \frac{\zeta^N - 1}{\zeta^{2^{n-1}} - 1} = \zeta^{2^{n-1}} + 1
$$

因此可以得到一个 $O(n)$ 的算法来计算 $s_i(\zeta)$ ，并且这里不含除法运算。计算过程是：$s_{n-1}(\zeta) \rightarrow s_{n-2}(\zeta) \rightarrow \cdots \rightarrow s_0(\zeta)$ 。

> - 可以先由随机数 $\zeta$ 计算出 $\zeta^2, \zeta^4, \ldots, \zeta^{2^{n - 1}}$ 次，这里由 $\zeta^2 = \zeta \times \zeta$ 需要一次有限域乘法，接着 $\zeta^4 = \zeta^2 \times \zeta^2$ ，需要一次有限域乘法，以此类推得到所有这些值，每次需要一次有限域乘法，总共会涉及 $n - 1$ 次有限域乘法，复杂度为 $(n - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。
> - 计算得到 $s_{n-1}(\zeta) = \zeta^{2^{n-1}} + 1$ ，这里只涉及有限域的加法，不计入复杂度中。
> - 计算 $s_{i}(\zeta) (i = 0, \ldots, n - 2)$ ，$s_{i}(\zeta) = s_{i + 1}(\zeta) \cdot (\zeta^{2^i} +1)$ 这里需要一次有限域乘法，因此需要的有限域乘法操作为 $\mathbb{F}_{\mathsf{mul}}$ ，取遍 $i = 0, \ldots, n - 2$ ，总复杂度为 $(n - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。
> 
> 因此总共的复杂度为
> 
> $$
>   (n - 1) ~ \mathbb{F}_{\mathsf{mul}} + (n - 1) ~ \mathbb{F}_{\mathsf{mul}} = 2(n - 1) ~ \mathbb{F}_{\mathsf{mul}}
> $$ 

2. 定义求值 Domain $D'$，包含 $n+1$ 个元素：

$$
D'=D\zeta = \{\zeta, \omega\zeta, \omega^2\zeta,\omega^4\zeta, \ldots, \omega^{2^{n-1}}\zeta\}
$$

3. 计算并发送 $c(X)$ 在 $D'$ 上的取值 

$$
c(\zeta), c(\zeta\cdot\omega), c(\zeta\cdot\omega^2), c(\zeta\cdot\omega^4), \ldots, c(\zeta\cdot\omega^{2^{n-1}})
$$

> Prover:
>
> 计算一个点在多项式 $C(X)$ 处的值，使用 Horner 方法，其涉及 $N$ 个有限域乘法，复杂度记为 $N ~\mathbb{F}_{\mathsf{mul}}$
> 
> ```python
> @staticmethod
> def evaluate_at_point(poly: list[F], point: F) -> F:
>     """Evaluate a polynomial at a single point using Horner's method."""
>     result = 0
>     for coeff in reversed(poly):
>         result = result * point + coeff
>     return result
> ```
> 
> 这里 $(1, \omega, \omega^2, \ldots, \omega^{2^{n - 1}})$ 可以提前计算好，因此计算点 $(\zeta, \zeta \cdot \omega, \zeta \cdot \omega^2, \ldots, \zeta \cdot \omega^{2^{n - 1}})$ 会涉及 $n$ 个有限域乘法，复杂度为 $n ~\mathbb{F}_{\mathsf{mul}}$ 。
> 
> 拿到这些点之后，再计算这些点在 $c(X)$ 处的值，总共要计算 $n + 1$ 个值，因此计算多项式的值的复杂度为 $(n+1)N ~\mathbb{F}_{\mathsf{mul}}$ 。
> 
> 因此在这一步的复杂度为
> 
> $$
> n ~\mathbb{F}_{\mathsf{mul}} + (n+1)N ~\mathbb{F}_{\mathsf{mul}} = (n + (n + 1)N) ~\mathbb{F}_{\mathsf{mul}}
> $$

4. 计算并发送 $z(\omega^{-1}\cdot\zeta)$

> Prover:
>
> 计算 $\omega^{-1}\cdot\zeta$ 复杂度为 $\mathbb{F}_{\mathsf{mul}}$ ，计算 $z(\omega^{-1}\cdot\zeta)$ 复杂度为 $N ~\mathbb{F}_{\mathsf{mul}}$ ，总复杂度为：
>
> $$
>   (N + 1) ~ \mathbb{F}_{\mathsf{mul}}
> $$

5. 计算 Linearized Polynomial $l_\zeta(X)$

$$
\begin{split}
l_\zeta(X) =& \Big(s_0(\zeta) \cdot (c(\zeta) - c_0) \\
& + \alpha\cdot s_0(\zeta) \cdot (u_{n-1}\cdot c(\zeta) - (1-u_{n-1})\cdot c(\omega^{2^{n-1}}\cdot\zeta))\\
  & + \alpha^2\cdot s_1(\zeta) \cdot (u_{n-2}\cdot c(\zeta) - (1-u_{n-2})\cdot c(\omega^{2^{n-2}}\cdot\zeta)) \\
  & + \cdots \\
  & + \alpha^{n-1}\cdot s_{n-2}(\zeta)\cdot (u_{1}\cdot c(\zeta) - (1-u_{1})\cdot c(\omega^2\cdot\zeta))\\
  & + \alpha^n\cdot s_{n-1}(\zeta)\cdot (u_{0}\cdot c(\zeta) - (1-u_{0})\cdot c(\omega\cdot\zeta)) \\
  & + \alpha^{n+1}\cdot (L_0(\zeta)\cdot\big(z(X) - c_0\cdot a(X))\\
  & + \alpha^{n+2}\cdot (\zeta - 1)\cdot\big(z(X)-z(\omega^{-1}\cdot\zeta)-c(\zeta)\cdot a(X) ) \\
  & + \alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(z(X) - v) \\
  & - v_H(\zeta)\cdot t(X)\ \Big)
\end{split}
$$

显然，$l_\zeta(\zeta)= 0$，因此这个运算值不需要发给 Verifier，并且 $[l_\zeta(\tau)]_1$ 可以由 Verifier 自行构造。

> Prover: 
> 
> - $s_0(\zeta) \cdot (c(\zeta) - c_0)$ ，涉及一次有限域乘法，复杂度为 $\mathbb{F}_{\mathsf{mul}}$
> - $\alpha \cdot s_0(\zeta) \cdot (u_{n-1}\cdot c(\zeta) - (1-u_{n-1})\cdot c(\omega^{2^{n-1}}\cdot\zeta))$ ，复杂度为 $4 ~ \mathbb{F}_{\mathsf{mul}}$ ，从第 $2$ 到 $n + 1$ 项都是如此，因此复杂度为 $4n ~ \mathbb{F}_{\mathsf{mul}}$
> - $\alpha^{n+1}\cdot L_0(\zeta)\cdot\big(z(X) - c_0\cdot a(X))\big)$  
>   - 在 Round 2 的第 4 步计算 $h_0(X)$ 时已经计算过 $z(X) - c_0\cdot a(X)$ ，因此这里可以直接用之前计算得到的结果。
>   - $L_0(X)$ 是预先计算得到的，那么得到 $L_0(\zeta)$ 的复杂度就是一个点在一个次数为 $N - 1$ 上的多项式求值的复杂度，由 $N$ 个系数，因此复杂度为 $N ~ \mathbb{F}_{\mathsf{mul}}$ 。
>   - $\alpha^{n+1}$ 在 Round 2 第 5 步已经计算得出，那么 $\alpha^{n+1}\cdot L_0(\zeta)$ 是两个有限域上的值相乘，复杂度为 $\mathbb{F}_{\mathsf{mul}}$ 。
>   - 通过代码实现可以看到这里其实会将 $\alpha^{n+1}\cdot L_0(\zeta)$ 变成一个常数多项式，然后和后面的多项式 $z(X) - c_0\cdot a(X)$ 相乘 。
>     ```python
>     r_poly += CnstPoly(alpha**(log_n + 1) * l0_poly_at_zeta) * (z_poly - CnstPoly(c_vec[0]) * f_poly)
>     ```
>   - 🎈 **perf** : 可以发现代码这里还有优化的空间，那就是 $z(X) - c_0\cdot a(X)$ 前面已经计算得到了，可以节省的复杂度是 $\mathsf{polymul}(0, N - 1)$ 。
>   - 计算多项式乘法 $\alpha^{n+1}\cdot L_0(\zeta)\cdot\big(z(X) - c_0\cdot a(X))\big)$ ，$\deg(\big(z(X) - c_0\cdot a(X))\big)) = N - 1$ ， $\deg(\alpha^{n+1}\cdot L_0(\zeta)) = 0$ ，复杂度为 $\mathsf{polymul}(0, N - 1)$ 。
>   - 因此这里计算 $\alpha^{n+1}\cdot L_0(\zeta)\cdot\big(z(X) - c_0\cdot a(X))\big)$ 总的复杂度为 $(N + 1) ~ \mathbb{F}_{\mathsf{mul}}  + \mathsf{polymul}(0, N - 1)$ 。
> - $\alpha^{n+2}\cdot (\zeta - 1)\cdot\big(z(X)-z(\omega^{-1}\cdot\zeta)-c(\zeta)\cdot a(X) )$
>   - $c(\zeta)\cdot a(X)$ ， $c(\zeta)$ 已在本轮的第 $3$ 步计算得到，复杂度为多项式的乘法，即 $\mathsf{polymul}(0, N - 1)$
>   - $z(\omega^{-1}\cdot\zeta)$ 在本轮第 $4$ 步已计算得到。
>   - $\alpha^{n+2}\cdot (\zeta - 1)$ 涉及一次有限域乘法，复杂度为 $\mathbb{F}_{\mathsf{mul}}$ 。
>   - 计算 $\alpha^{n+2}\cdot (\zeta - 1)\cdot\big(z(X)-z(\omega^{-1}\cdot\zeta)-c(\zeta)\cdot a(X) \big)$ 为两个多项式的乘法，$\deg(\alpha^{n+2}\cdot (\zeta - 1)) = 0$ ，$\deg\big(z(X)-z(\omega^{-1}\cdot\zeta)-c(\zeta)\cdot a(X) \big) = N - 1$ ，因此复杂度为 $\mathsf{polymul}(0, N - 1)$ 。
>   - 这一步计算的总复杂度为 $\mathbb{F}_{\mathsf{mul}} + 2~\mathsf{polymul}(0, N - 1)$ 。
> - $\alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(z(X) - v)$
>   - $L_{N-1}(\zeta)$ ，$L_{N-1}(X)$ 是预先计算得到的，有 $N$ 个系数，计算在一点的值，复杂度为 $N ~ \mathbb{F}_{\mathsf{mul}}$ 。
>   - $\alpha^{n+3}\cdot L_{N-1}(\zeta)$ 复杂度为 $\mathbb{F}_{\mathsf{mul}}$ 。
>   - $\alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(z(X) - v)$ 为两个多项式相乘，复杂度为 $\mathsf{polymul}(0, N - 1)$ 。
>   - 这一步计算的总复杂度为 $(N + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - 1)$ 。
> - $v_H(\zeta)\cdot t(X)$
>   - $v_H(\zeta)$ ，$v_H(X)$ 的次数为 $N$ ，有 $N + 1$ 个系数，计算求值复杂度为 $(N + 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。
>   - $v_H(\zeta)\cdot t(X)$ ，其中 $\deg(t(X)) = 2N - 1 - N = N - 1$ ，因此这里多项式乘法的复杂度为 $\mathsf{polymul}(0, N - 1)$ 。
>   - 这一步计算的总复杂度为 $(N + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - 1)$ 。
> 
> 因此，在这一步计算 $l_{\zeta}(X)$ 的复杂度总计为
> 
> $$
> \begin{aligned}
>   & \mathbb{F}_{\mathsf{mul}} + 4n ~ \mathbb{F}_{\mathsf{mul}} + (N + 1) ~ \mathbb{F}_{\mathsf{mul}}  + \mathsf{polymul}(0, N - 1) + \mathbb{F}_{\mathsf{mul}} \\
>   & + 2 ~ \mathsf{polymul}(0, N - 1) + (N + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - 1) + (N + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - 1) \\
>   = & (3N + 4n + 5) ~ \mathbb{F}_{\mathsf{mul}} + 5 ~ \mathsf{polymul}(0, N - 1) 
> \end{aligned}
> $$

6. 构造多项式 $c^*(X)$，它是下面向量在 $D\zeta$ 上的插值多项式

$$
\vec{c^*}= \Big(c(\omega\cdot\zeta), c(\omega^2\cdot\zeta), c(\omega^4\cdot\zeta), \ldots, c(\omega^{2^{n-1}}\cdot\zeta), c(\zeta)\Big)
$$

Prover 可以利用事先预计算的 $D$ 上的Bary-Centric Weights $\{\hat{w}_i\}$ 来快速计算 $c^*(X)$，

$$
c^*(X) = \frac{c^*_0 \cdot \frac{\hat{w}_0}{X-\omega\zeta} + c^*_1 \cdot \frac{\hat{w}_1}{X-\omega^{2}\zeta} + \cdots + c^*_n \cdot \frac{\hat{w}_n}{X-\omega^{2^n}\zeta}}{
   \frac{\hat{w}_0}{X-\omega\zeta} + \frac{\hat{w}_1}{X-\omega^2\zeta} + \cdots + \frac{\hat{w}_n}{X-\omega^{2^n}\zeta}
  }
$$

这里 $\hat{w}_j$ 为预计算的值：

$$
\hat{w}_j = \prod_{l\neq j} \frac{1}{\omega^{2^j} - \omega^{2^l}}
$$

> Prover:
> 
> - $\vec{c^*}$ 与 $\omega^{2^i}\zeta$ 的值在本轮的第 $3$ 步已经计算得到。
> - 计算 $\frac{\hat{w}_i}{X-\omega^{2^i}\zeta}$ ，分子是一个常数，分母是一个一次多项式，复杂度记为 $\mathsf{polydiv}(0, 1)$ ，得到的结果其实是一个分式。
> - 计算 $c_i^* \cdot \frac{\hat{w}_i}{X-\omega^{2^i}\zeta}$ ，这里将复杂度记为 $\mathsf{polymul}(0, -1)$ 。
> - 最后计算 $c^*(X)$ ，分子和分母分别通分后，分子分母均为一个次数为 $n$ 的多项式，因此它们相除的复杂度记为 $\mathsf{polydiv}(n, n)$ ，最后得到的结果 $c^*(X)$ 次数也为 $n$ 。
> 
> 多项式相加的复杂度只涉及有限域的加法，不做计入，因此这一步 $c^*(X)$ 的复杂度为 
>  
>  $$
>  n ~ \mathsf{polymul}(0, -1) + n ~\mathsf{polydiv}(0, 1) + \mathsf{polydiv}(n, n) 
>  $$



7. 因为 $l_\zeta(\zeta)= 0$，所以存在 Quotient 多项式 $q_\zeta(X)$ 满足

$$
q_\zeta(X) = \frac{1}{X-\zeta}\cdot l_\zeta(X)
$$

> 这一步的计算采用的是下面的算法，代码为
> 
> ```python
> def division_by_linear_divisor(self, d):
>     """
>     Divide a polynomial by a linear divisor (X - d) using Ruffini's rule.
> 
>     Args:
>         coeffs (list): Coefficients of the polynomial, from lowest to highest degree.
>         d (Scalar): The constant term of the linear divisor.
> 
>     Returns:
>         tuple: (quotient coefficients, remainder)
>     """
>     assert len(self.coeffs) > 0, "Polynomial degree must be at least 1"
> 
>     n = len(self.coeffs)
>     quotient = [0] * (n - 1)
>     
>     # Start with the highest degree coefficient
>     current = self.coeffs[-1]
>     
>     # Iterate through coefficients from second-highest to lowest degree
>     for i in range(n - 2, -1, -1):
>         # Store the current value in the quotient
>         quotient[i] = current
>         
>         # Compute the next value
>         current = current * d + self.coeffs[i]
>     
>     # The final current value is the remainder
>     remainder = current
> 
>     return UniPolynomial(quotient), remainder
> ```
> 
> 对于一个 $n$ 次的多项式 
> 
> $$
> f(X) = f_0 + f_1 X + f_2 X^2 + \cdots + f_{n-1} X^{n-1} + f_n X^n
> $$
> 
> 除上一个一次多项式 $X - d$ ，想得到其商多项式和余项，即满足 $f(X) = q(X)(X - d) + r(X)$ ，那么可以这样来分解
> 
> $$
> \begin{aligned}
>   & f_0 + f_1 X + f_2 X^2 + \cdots + f_{n-1} X^{n-1} + f_n X^n  \\
>   = & (X -  d)(f_n \cdot X^{n - 1}) + d \cdot f_n \cdot X^{n - 1} + f_{n - 1} X^{n - 1} + \cdots + f_1 X + f_0 \\
>   = & (X -  d)(f_n \cdot X^{n - 1}) + (X - d)((df_n + f_{n - 1}) \cdot X^{n - 2}) \\
>   & + d \cdot (df_n + f_{n - 1}) + f_{n - 2} X^{n - 2} + \cdots + f_1 X + f_0 \\
> \end{aligned}
> $$
> 
> 通过上式子发现，
> 
> $$
> \begin{aligned}
>   & q_{n - 1} = f_n \\
>   & q_i = d \cdot q_{i + 1} + f_{i + 1} , \quad i = n - 2, \ldots, 0 \\
> \end{aligned}
> $$
> 
> 因此最后的余项为
> 
> $$
> r(X) = d \cdot q_0 + f_0
> $$
> 
> 这里 $i$ 从 $n - 2, \ldots, 0$ ，每次会涉及一次有限域乘法，最后算 $r(X)$ 也涉及一次乘法，因此复杂度为 $n ~ \mathbb{F}_{\mathsf{mul}}$ 。
> 
> 回到分析计算 $q_\zeta(X)$ 的复杂度，需要分析 $l_\zeta(X)$ 的次数。
> 
> $$
> \begin{split}
> l_\zeta(X) =& \Big(s_0(\zeta) \cdot (c(\zeta) - c_0) \\
> & + \alpha\cdot s_0(\zeta) \cdot (u_{n-1}\cdot c(\zeta) - (1-u_{n-1})\cdot c(\omega^{2^{n-1}}\cdot\zeta))\\
>   & + \alpha^2\cdot s_1(\zeta) \cdot (u_{n-2}\cdot c(\zeta) - (1-u_{n-2})\cdot c(\omega^{2^{n-2}}\cdot\zeta)) \\
>   & + \cdots \\
>   & + \alpha^{n-1}\cdot s_{n-2}(\zeta)\cdot (u_{1}\cdot c(\zeta) - (1-u_{1})\cdot c(\omega^2\cdot\zeta))\\
>   & + \alpha^n\cdot s_{n-1}(\zeta)\cdot (u_{0}\cdot c(\zeta) - (1-u_{0})\cdot c(\omega\cdot\zeta)) \\
>   & + \alpha^{n+1}\cdot (L_0(\zeta)\cdot\big(z(X) - c_0\cdot a(X))\\
>   & + \alpha^{n+2}\cdot (\zeta - 1)\cdot\big(z(X)-z(\omega^{-1}\cdot\zeta)-c(\zeta)\cdot a(X) \big) \\
>   & + \alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(z(X) - v) \\
>   & - v_H(\zeta)\cdot t(X)\ \Big)
> \end{split}
> $$
> 
> 前面几项都为常数，
> - $\alpha^{n+1}\cdot (L_0(\zeta)\cdot\big(z(X) - c_0\cdot a(X))$ 的次数为 $N - 1 + N - 1 = 2N - 2$ 。
> - $\alpha^{n+2}\cdot (\zeta - 1)\cdot\big(z(X)-z(\omega^{-1}\cdot\zeta)-c(\zeta)\cdot a(X) \big)$ 的次数为 $N - 1$ 。
> - $\alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(z(X) - v)$ 的次数为 $N - 1 + N - 1 = 2N - 2$ 。$v_H(\zeta)\cdot t(X)$ 的次数为 $2N - 1$ 。
> 
> 因此 $l_\zeta(X)$ 的次数为 $2N - 1$ 。因此计算 $q_\zeta(X)$ 的复杂度为 $(2N - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。


8. 构造 $D\zeta$ 上的消失多项式 $z_{D_{\zeta}}(X)$

$$
z_{D_{\zeta}}(X) = (X-\zeta\omega)\cdots (X-\zeta\omega^{2^{n-1}})(X-\zeta)
$$

> 这步的复杂度为 $n \log^2n ~ \mathbb{F}_{\mathsf{mul}}$
> 
> - [ ] 查看算法弄懂

9. 构造 Quotient 多项式  $q_c(X)$ :

$$
q_c(X) = \frac{(c(X) - c^*(X))}{(X-\zeta)(X-\omega\zeta)(X-\omega^2\zeta)\cdots(X-\omega^{2^{n-1}}\zeta)}
$$

> 分母的多项式即为第 $8$ 步的 $z_{D_{\zeta}}(X)$ ，这里的复杂度为两个多项式的除法，
> - $c(X) - c^*(X)$ 的次数为 $N - 1$
> - $z_{D_{\zeta}}(X)$ 的次数为 $n + 1$
> 
> 因此这步的复杂度为 $\mathsf{polydiv}(N - 1, n + 1)$

10.  构造 Quotient 多项式 $q_{\omega\zeta}(X)$

$$
q_{\omega\zeta}(X) = \frac{z(X) - z(\omega^{-1}\cdot\zeta)}{X - \omega^{-1}\cdot\zeta}
$$

> 在本轮的第 $4$ 步已经得到 $z(\omega^{-1}\cdot\zeta)$ ，也可以用在 $4$ 步得到的 $\omega^{-1}\cdot\zeta$ ，这里依然可以用线性多项式的除法算法，分子多项式 $z(X) - z(\omega^{-1}\cdot\zeta)$ 的次数为 $N - 1$ ，因此这步的复杂度为 $(N - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。

11.  发送 $\big(Q_c = [q_c(\tau)]_1, Q_\zeta=[q_\zeta(\tau)]_1, Q_{\omega\zeta}=[q_{\omega\zeta}(\tau)]_1,  \big)$

> - $Q_c$: $\deg(q_c) = N - 1 - (n + 1) = N - n - 2$ ，复杂度为 $\mathsf{msm}(N - n - 1, \mathbb{G}_1)$
> - $Q_\zeta$: $\deg(q_\zeta) = 2N - 2$ ，复杂度为 $\mathsf{msm}(2N - 1, \mathbb{G}_1)$
> - $Q_{\omega\zeta}$: $\deg(q_{\omega\zeta}) = N - 2$ ，复杂度为 $\mathsf{msm}(N - 1, \mathbb{G}_1)$
>
> 因此这步总的复杂度为 $\mathsf{msm}(N - n - 1, \mathbb{G}_1) + \mathsf{msm}(2N - 1, \mathbb{G}_1) + \mathsf{msm}(N - 1, \mathbb{G}_1)$


> #### Round 3 复杂度
> 
> Prover:
> 
> $$
> \begin{aligned}
>   & 2(n - 1) ~ \mathbb{F}_{\mathsf{mul}} \\
>   & + (n + (n + 1)N) ~\mathbb{F}_{\mathsf{mul}} \\
>   & + (N + 1) ~ \mathbb{F}_{\mathsf{mul}} \\
>   & + (3N + 4n + 5) ~ \mathbb{F}_{\mathsf{mul}} + 5 ~ \mathsf{polymul}(0, N - 1)  \\
>   & + n ~ \mathsf{polymul}(0, -1) + n ~\mathsf{polydiv}(0, 1) + \mathsf{polydiv}(n, n)  \\
>   & + (2N - 1) ~ \mathbb{F}_{\mathsf{mul}} \\
>   & + n \log^2n ~ \mathbb{F}_{\mathsf{mul}} \\
>   & + \mathsf{polydiv}(N - 1, n + 1) \\
>   & + (N - 1) ~ \mathbb{F}_{\mathsf{mul}} \\
>   & + \mathsf{msm}(N - n - 1, \mathbb{G}_1) + \mathsf{msm}(2N - 1, \mathbb{G}_1) + \mathsf{msm}(N - 1, \mathbb{G}_1) \\
>   = & (nN + 8N + n \log^2n + 7n  + 2) ~ \mathbb{F}_{\mathsf{mul}} + 5 ~ \mathsf{polymul}(0, N - 1) + n ~ \mathsf{polymul}(0, -1) \\
>   & + n ~\mathsf{polydiv}(0, 1) + \mathsf{polydiv}(n, n) + \mathsf{polydiv}(N - 1, n + 1) \\
>   & + \mathsf{msm}(N - n - 1, \mathbb{G}_1) + \mathsf{msm}(2N - 1, \mathbb{G}_1) + \mathsf{msm}(N - 1, \mathbb{G}_1)
> \end{aligned}
> $$

#### Round 4.

1. Verifier 发送第二个随机挑战点 $\xi\leftarrow_{\$}\mathbb{F}_p$ 

2. Prover 构造第三个 Quotient 多项式 $q_\xi(X)$

$$
q_\xi(X) = \frac{c(X) - c^*(\xi) - z_{D_\zeta}(\xi)\cdot q_c(X)}{X-\xi}
$$

> Prover:
> - $c^*(X)$ 的次数为 $N - 1$ ，因此计算 $c^*(\xi)$ 的复杂度为 $N ~ \mathbb{F}_{\mathsf{mul}}$
> - $z_{D_\zeta}(X)$ 的次数为 $n + 1$ ，因此计算 $z_{D_\zeta}(\xi)$ 的复杂度为 $(n + 2) ~ \mathbb{F}_{\mathsf{mul}}$
> - $z_{D_\zeta}(\xi)\cdot q_c(X)$ ，为多项式乘法，复杂度为 $\mathsf{polymul}(0, N - 1 - (n + 1))$ ，即 $\mathsf{polymul}(0, N - n - 2)$
> - 计算 $\frac{c(X) - c^*(\xi) - z_{D_\zeta}(\xi)\cdot q_c(X)}{X-\xi}$ 可以用到线性除法，分母多项式的次数为 $N - 1$ ，因此这里的复杂度为 $(N - 1) ~ \mathbb{F}_{\mathsf{mul}}$
>
> 这一步的总复杂度为
>
> $$
> N ~ \mathbb{F}_{\mathsf{mul}} + (n + 2) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - n - 2) + (N - 1) ~ \mathbb{F}_{\mathsf{mul}} = (2N + n + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - n - 2)
> $$

3. Prover 计算并发送 $Q_\xi$

$$
Q_\xi = \mathsf{KZG10.Commit}(q_\xi(X)) = [q_\xi(\tau)]_1
$$

> Prover:
> - $Q_\xi$： $\deg(q_\xi) = N - 2$ ，复杂度为 $\mathsf{msm}(N - 1, \mathbb{G}_1)$

> #### Round4 复杂度
>
> Prover:
>
> $$
> (2N + n + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - n - 2) + \mathsf{msm}(N - 1, \mathbb{G}_1)
> $$

### 证明表示

$7\cdot\mathbb{G}_1$, $(n+1)\cdot\mathbb{F}_{p}$ 

$$
\begin{aligned}
\pi_{eval} &= \big(z(\omega^{-1}\cdot\zeta), c(\zeta)，c(\omega\cdot\zeta), c(\omega^2\cdot\zeta), c(\omega^4\cdot\zeta), \ldots, c(\omega^{2^{n-1}}\cdot\zeta), \\
& \qquad C_{c}, C_{t}, C_{z}, Q_c, Q_\zeta, Q_\xi, Q_{\omega\zeta}\big)
\end{aligned}
$$


### 验证过程

1. Verifier 计算 $c^*(\xi)$ 使用预计算的 Barycentric Weights $\{\hat{w}_i\}$

$$
c^*(\xi)=\frac{\sum_i c_i^*\frac{\hat{w}_i}{\xi-x_i}}{\sum_i \frac{\hat{w}_i}{\xi-x_i}}
$$

再计算对应的承诺 $C^*(\xi)=[c^*(\xi)]_1$ 。

> Verifier:
> 
> - 先分析每一项计算的复杂度，计算 $\frac{\hat{w}_i}{\xi-x_i}$ ，分子 $\hat{w}_i$ 可以由预计算得到，分母 $\xi-x_i$ 计算得到后要计算其逆元，再和 $\hat{w}_i$ 相乘，因此这里的复杂度为 $\mathbb{F}_{\mathsf{mul}} + \mathbb{F}_{\mathsf{inv}}$ 。
> - 计算 $c_i^*\frac{\hat{w}_i}{\xi-x_i}$ ，复杂度为 $\mathbb{F}_{\mathsf{mul}}$ 。
> - 最后将分子分母得到有限域上的值相除，其实就是分母的值求逆，再和分子相乘，复杂度为 $\mathbb{F}_{\mathsf{mul}} + \mathbb{F}_{\mathsf{inv}}$ 。
> - 计算得到 $c^*(\xi)$ 后计算其承诺 $C^*(\xi)$ ，复杂度为 $\mathsf{EccMul}^{\mathbb{G}_1}$
> 
> 因此这一步的总复杂度为 
>
> $$
> \begin{aligned}
>   & (n + 1) ~ (\mathbb{F}_{\mathsf{mul}} + \mathbb{F}_{\mathsf{inv}}) + (n + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathbb{F}_{\mathsf{mul}} + \mathbb{F}_{\mathsf{inv}} + \mathsf{EccMul}^{\mathbb{G}_1} \\
>  = & (2n + 3) ~ \mathbb{F}_{\mathsf{mul}} + (n + 2) ~ \mathbb{F}_{\mathsf{inv}} + \mathsf{EccMul}^{\mathbb{G}_1}
> \end{aligned}
> $$


2. Verifier 计算 $v_H(\zeta), L_0(\zeta), L_{N-1}(\zeta)$ 


$$
v_H(\zeta) = \zeta^N - 1
$$

$$
L_0(\zeta) = \frac{1}{N}\cdot \frac{v_{H}(\zeta)}{\zeta-1}
$$

$$
L_{N-1}(\zeta) = \frac{\omega^{N-1}}{N}\cdot \frac{v_{H}(\zeta)}{\zeta-\omega^{N-1}}
$$

> Verifier:
> - $v_H(\zeta)$ : $\zeta^N$ 可以用 $\log N$ 次有限域乘法计算得到，复杂度为 $\log N ~ \mathbb{F}_{\mathsf{mul}}$
> - $L_0(\zeta)$ : $1/N$ 可以在预计算中给出。计算 $\zeta-1$ 的逆元，涉及一次有限域中元素的求逆操作，复杂度记为 $\mathbb{F}_{\mathsf{inv}}$ ，$\zeta-1$ 的逆元与 $v_{H}(\zeta)$ 相乘，涉及一次有限域中的乘法操作，为 $\mathbb{F}_{\mathsf{mul}}$ ，其结果再与 $1/N$ 相乘，复杂度为 $\mathbb{F}_{\mathsf{mul}}$ ，因此这一步的总复杂度为 $\mathbb{F}_{\mathsf{inv}} + 2 ~ \mathbb{F}_{\mathsf{mul}}$ 。
> - $L_{N-1}(\zeta)$ : $\omega^{N-1}/N$ 可以在预计算中给出。计算 $\zeta-\omega^{N-1}$ 的逆元，涉及一次有限域中元素的求逆操作，复杂度记为 $\mathbb{F}_{\mathsf{inv}}$ ，$\zeta-\omega^{N-1}$ 的逆元与 $v_{H}(\zeta)$ 相乘，涉及一次有限域中的乘法操作，为 $\mathbb{F}_{\mathsf{mul}}$ ，其结果再与 $\omega^{N-1}/N$ 相乘，复杂度为 $\mathbb{F}_{\mathsf{mul}}$ ，因此这一步的总复杂度为 $\mathbb{F}_{\mathsf{inv}} + 2 ~ \mathbb{F}_{\mathsf{mul}}$ 。
>
> 因此这一步的总复杂度为 $2 ~ \mathbb{F}_{\mathsf{inv}} + (\log N + 4) ~ \mathbb{F}_{\mathsf{mul}}$

3. Verifier 计算 $s_0(\zeta), \ldots, s_{n-1}(\zeta)$ ，其计算方法可以采用前文提到的递推方式进行计算。

> Verifier:
> 
> 与在 Round 3 中第 $1$ 步的分析一致，这一步的复杂度为 $2(n - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。


4. Verifier 计算 $z_{D_\zeta}(\xi)$ ，
   
$$
z_{D_{\zeta}}(\xi) = (\xi-\zeta\omega)\cdots (\xi-\zeta\omega^{2^{n-1}})(\xi-\zeta)
$$

> Verifier:
> 
> $\xi-\zeta\omega^i$ 的计算在本轮的第 $1$ 步已经计算得到，因此这里的复杂度主要为 $n$ 个有限域上的数相乘，复杂度为 $(n - 1) ~ \mathbb{F}_{\mathsf{mul}}$ 。

5. Verifier 计算线性化多项式的承诺 $C_l$ 


$$
\begin{split}
C_l & = 
\Big( \Big((c(\zeta) - c_0)s_0(\zeta) \\
& + \alpha \cdot (u_{n-1}\cdot c(\zeta) - (1-u_{n-1})\cdot c(\omega^{2^{n-1}}\cdot\zeta))\cdot s_0(\zeta)\\
  & + \alpha^2\cdot (u_{n-2}\cdot c(\zeta) - (1-u_{n-2})\cdot c(\omega^{2^{n-2}}\cdot\zeta))\cdot s_1(\zeta)  \\
  & + \cdots \\
  & + \alpha^{n-1}\cdot (u_{1}\cdot c(\zeta) - (1-u_{1})\cdot c(\omega^2\cdot\zeta))\cdot s_{n-2}(\zeta)\\
  & + \alpha^n\cdot (u_{0}\cdot c(\zeta) - (1-u_{0})\cdot c(\omega\cdot\zeta))\cdot s_{n-1}(\zeta) \Big) \cdot [1]_1 \\
  & + \alpha^{n+1}\cdot L_0(\zeta)\cdot(C_z - c_0\cdot C_a)\\
  & + \alpha^{n+2}\cdot (\zeta-1)\cdot\big(C_z - z(\omega^{-1}\cdot \zeta)\cdot [1]_1-c(\zeta)\cdot C_{a} ) \\
  & + \alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(C_z - v \cdot [1]_1) \\
  & - v_H(\zeta)\cdot C_t \Big)
\end{split}
$$

> Verifier: 
>
> - 先计算 $\alpha^2, \ldots, \alpha^{n+3}$ ，这里涉及 $n + 2$ 次有限域乘法，复杂度为 $(n + 2) ~ \mathbb{F}_{\mathsf{mul}}$ 。
> - $s_0(\zeta) \cdot (c(\zeta) - c_0)$ ，涉及一次有限域乘法，复杂度为 $\mathbb{F}_{\mathsf{mul}}$
> - $\alpha \cdot s_0(\zeta) \cdot (u_{n-1}\cdot c(\zeta) - (1-u_{n-1})\cdot c(\omega^{2^{n-1}}\cdot\zeta))$ ，复杂度为 $4 ~ \mathbb{F}_{\mathsf{mul}}$ ，从第 $2$ 到 $n + 1$ 项都是如此，因此复杂度为 $4n ~ \mathbb{F}_{\mathsf{mul}}$
> - 将上面计算的结果相加得到一个有限域的值，再与 $[1]_1$ 相乘，复杂度为 $\mathsf{EccMul}^{\mathbb{G}_1}$
> - $\alpha^{n+1}\cdot L_0(\zeta)\cdot(C_z - c_0\cdot C_a)$  
>   - $c_0\cdot C_a$ 复杂度为 $\mathsf{EccMul}^{\mathbb{G}_1}$
>   - $C_z - c_0\cdot C_a$ 涉及椭圆曲线的减法，但是椭圆曲线的减法是由椭圆曲线上的加法转换的，$P_1 - P_2 = P_1 + (-P_2)$ ，而设 $P_2 = (x_2, y_2)$ ，那么 $-P_2 = (x_2, -y_2)$ ，这里 $x_2, y_2$ 都是有限域上的值，因此相比椭圆曲线上的加法，多了一次有限域上取负数的操作，可由有限域上的加法完成，这里复杂度不做计入。因此这步的复杂度记为 $\mathsf{EccAdd}^{\mathbb{G}_1}$
> 
>     > 📝 关于椭圆曲线上的加法或减法 python 实现可参考 [py_ecc](https://github.com/ethereum/py_ecc/blob/main/py_ecc/bn128/bn128_curve.py) 。
>
>   - $\alpha^{n+1}\cdot L_0(\zeta)$ ，复杂度为 $\mathbb{F}_{\mathsf{mul}}$
>   - $\alpha^{n+1}\cdot L_0(\zeta)\cdot(C_z - c_0\cdot C_a)$ ，将上面计算的结果进行相乘，复杂度为 $\mathsf{EccMul}^{\mathbb{G}_1}$
>   - 因此计算这一步的总复杂度为 $\mathbb{F}_{\mathsf{mul}} + 2 ~ \mathsf{EccMul}^{\mathbb{G}_1} + \mathsf{EccAdd}^{\mathbb{G}_1}$
> - $\alpha^{n+2}\cdot (\zeta-1)\cdot\big(C_z - z(\omega^{-1}\cdot \zeta)\cdot [1]_1-c(\zeta)\cdot C_{a} \big)$
>   - $c(\zeta)\cdot C_{a}$ : $\mathsf{EccMul}^{\mathbb{G}_1}$
>   - $z(\omega^{-1}\cdot \zeta)\cdot [1]_1$ : $\mathsf{EccMul}^{\mathbb{G}_1}$
>   - $C_z - z(\omega^{-1}\cdot \zeta)\cdot [1]_1-c(\zeta)\cdot C_{a}$ : $2 ~\mathsf{EccAdd}^{\mathbb{G}_1}$
>   - $\alpha^{n+2}\cdot (\zeta-1)$: $\mathbb{F}_{\mathsf{mul}}$
>   - $\alpha^{n+2}\cdot (\zeta-1)\cdot\big(C_z - z(\omega^{-1}\cdot \zeta)\cdot [1]_1-c(\zeta)\cdot C_{a} \big)$: $\mathsf{EccMul}^{\mathbb{G}_1}$
>   - 总计： $\mathbb{F}_{\mathsf{mul}} + 3~\mathsf{EccMul}^{\mathbb{G}_1} + 2 ~\mathsf{EccAdd}^{\mathbb{G}_1}$
> - $\alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(C_z - v \cdot [1]_1)$ 
>   - $v \cdot [1]_1$: $\mathsf{EccMul}^{\mathbb{G}_1}$
>   - $C_z - v \cdot [1]_1$: $\mathsf{EccAdd}^{\mathbb{G}_1}$
>   - $\alpha^{n+3}\cdot L_{N-1}(\zeta)\cdot(C_z - v \cdot [1]_1)$: $\mathbb{F}_{\mathsf{mul}} + \mathsf{EccMul}^{\mathbb{G}_1}$
>   - 总计： $\mathbb{F}_{\mathsf{mul}} + 2~\mathsf{EccMul}^{\mathbb{G}_1} + \mathsf{EccAdd}^{\mathbb{G}_1}$
> - $v_H(\zeta)\cdot C_t$: $\mathsf{EccMul}^{\mathbb{G}_1}$
> - 将上面所有结果相加，涉及椭圆曲线上 $4$ 次加法，复杂度为 $4 ~ \mathsf{EccAdd}^{\mathbb{G}_1}$
> 
> 因此，在这一步计算 $l_{\zeta}(X)$ 的复杂度总计为
> 
> $$
> \begin{aligned}
>   & (n + 2 + 1 + 4n) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{EccMul}^{\mathbb{G}_1} \\
>   & + \mathbb{F}_{\mathsf{mul}} + 2~\mathsf{EccMul}^{\mathbb{G}_1} + \mathsf{EccAdd}^{\mathbb{G}_1} \\
>   & + \mathbb{F}_{\mathsf{mul}} + 3~\mathsf{EccMul}^{\mathbb{G}_1} + 2 ~\mathsf{EccAdd}^{\mathbb{G}_1} \\
>   & + \mathbb{F}_{\mathsf{mul}} + 2~\mathsf{EccMul}^{\mathbb{G}_1} + \mathsf{EccAdd}^{\mathbb{G}_1} \\
>   & + \mathsf{EccMul}^{\mathbb{G}_1} + 4 ~ \mathsf{EccAdd}^{\mathbb{G}_1} \\
>   = & (5n + 6) ~ \mathbb{F}_{\mathsf{mul}} + 9 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 8 ~ \mathsf{EccAdd}^{\mathbb{G}_1}
> \end{aligned}
> $$

6. Verifier 产生随机数 $\eta$ 来合并下面的 Pairing 验证：

$$
\begin{split}
e(C_l + \zeta\cdot Q_\zeta, [1]_2)\overset{?}{=}e(Q_\zeta, [\tau]_2)\\
e(C_c - C^*(\xi) - z_{D_\zeta}(\xi)\cdot Q_c + \xi\cdot Q_\xi, [1]_2) \overset{?}{=} e(Q_\xi, [\tau]_2)\\
e(C_z + \zeta\cdot Q_{\omega\zeta} - z(\omega^{-1}\cdot\zeta)\cdot[1]_1, [1]_2) \overset{?}{=} e(Q_{\omega\zeta}, [\tau]_2)\\
\end{split}
$$

合并后的验证只需要两个 Pairing 运算。


$$
\begin{split}

P &= \Big(C_l + \zeta\cdot Q_\zeta\Big) \\

& + \eta\cdot \Big(C_c - C^*(\xi) - z_{D_\zeta}(\xi)\cdot Q_c + \xi\cdot Q_\xi\Big) \\

& + \eta^2\cdot\Big(C_z + \zeta\cdot Q_{\omega\zeta} - z(\omega^{-1}\cdot\zeta)\cdot[1]_1\Big)

\end{split}
$$

$$
e\Big(P, [1]_2\Big) \overset{?}{=} e\Big(Q_\zeta + \eta\cdot Q_\xi + \eta^2\cdot Q_{\omega\zeta}, [\tau]_2\Big)
$$

> Verifier:
> 
> - 可以先计算出 $\eta^2$ ，复杂度为 $\mathbb{F}_{\mathsf{mul}}$
> - $\Big(C_l + \zeta\cdot Q_\zeta\Big)$: $\mathsf{EccMul}^{\mathbb{G}_1} + \mathsf{EccAdd}^{\mathbb{G}_1}$
> - $\eta\cdot \Big(C_c - C^*(\xi) - z_{D_\zeta}(\xi)\cdot Q_c + \xi\cdot Q_\xi\Big)$ :
> 
>   $$
>   2 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 3 ~ \mathsf{EccAdd}^{\mathbb{G}_1} + \mathsf{EccMul}^{\mathbb{G}_1} = 3 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 3 ~ \mathsf{EccAdd}^{\mathbb{G}_1}
>   $$
> - $\eta^2\cdot\Big(C_z + \zeta\cdot Q_{\omega\zeta} - z(\omega^{-1}\cdot\zeta)\cdot[1]_1\Big)$:  $3 ~\mathsf{EccMul}^{\mathbb{G}_1} + 2~\mathsf{EccAdd}^{\mathbb{G}_1}$
> - 计算 $P$ ，需要将上面的结果进行相加，复杂度为 $2 ~ \mathsf{EccAdd}^{\mathbb{G}_1}$
> - $e\Big(P, [1]_2\Big)$ ，涉及一次椭圆曲线 pairing 操作，记为 $P$
> - $Q_\zeta + \eta\cdot Q_\xi + \eta^2\cdot Q_{\omega\zeta}$: $2 ~\mathsf{EccMul}^{\mathbb{G}_1} + 2 ~ \mathsf{EccAdd}^{\mathbb{G}_1}$
> - $e\Big(Q_\zeta + \eta\cdot Q_\xi + \eta^2\cdot Q_{\omega\zeta}, [\tau]_2\Big)$ ，涉及一次椭圆曲线 pairing 操作，复杂度为 $P$
> 
> 将上面的所有结果相加，得到这一步的总复杂度为
> 
> $$
> \begin{aligned}
>   & \mathbb{F}_{\mathsf{mul}} + \mathsf{EccMul}^{\mathbb{G}_1} + \mathsf{EccAdd}^{\mathbb{G}_1} \\
>   & + 3 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 3 ~ \mathsf{EccAdd}^{\mathbb{G}_1} \\
>   & + 3 ~\mathsf{EccMul}^{\mathbb{G}_1} + 2~\mathsf{EccAdd}^{\mathbb{G}_1} \\
>   & + 2 ~ \mathsf{EccAdd}^{\mathbb{G}_1} + P + 2 ~\mathsf{EccMul}^{\mathbb{G}_1} + P \\
>   = & \mathbb{F}_{\mathsf{mul}} + 9 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 8 ~ \mathsf{EccAdd}^{\mathbb{G}_1} + 2 ~ P
> \end{aligned}
> $$


## 协议复杂度汇总

### Commit Phase

**Prover's cost:**

$$
N\log N ~\mathbb{F}_{\mathsf{mul}} + \mathsf{msm}(N, \mathbb{G}_1)
$$

### Evaluation Protocol

**Prover's cost:**

$$
\begin{aligned}
  & (N - 1) ~ \mathbb{F}_{\mathsf{mul}} + N \log N ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{msm}(N, \mathbb{G}_1) \\
  & + ((n + 2)N + N \log N + 2) ~ \mathbb{F}_{\mathsf{mul}}  \\
  & + (2n + 1) ~ \mathsf{polymul}(0, N - 1) + \mathsf{polymul}(0, 2N - 1) + 2~\mathsf{polymul}(0, 2N - 2) +  \mathsf{polymul}(1, 2N - 2)  \\
  & + 4 ~ \mathsf{polymul}(N - 1, N - 1)+ \sum_{k = 1}^{n} \mathsf{polymul}(N - 2^{k - 1}, N - 1) + \sum_{k = 1}^{n} \mathsf{polymul}(0, 2N - 2^{k - 1} - 1) \\
  & + \mathsf{polydiv}(2N - 1, N) \\
  & + 2 ~ \mathsf{msm}(N, \mathbb{G}_1) \\
  & + (nN + 8N + n \log^2n + 7n  + 2) ~ \mathbb{F}_{\mathsf{mul}} + 5 ~ \mathsf{polymul}(0, N - 1) + n ~ \mathsf{polymul}(0, -1) \\
  & + n ~\mathsf{polydiv}(0, 1) + \mathsf{polydiv}(n, n) + \mathsf{polydiv}(N - 1, n + 1) \\
  & + \mathsf{msm}(N - n - 1, \mathbb{G}_1) + \mathsf{msm}(2N - 1, \mathbb{G}_1) + \mathsf{msm}(N - 1, \mathbb{G}_1) \\
  & + (2N + n + 1) ~ \mathbb{F}_{\mathsf{mul}} + \mathsf{polymul}(0, N - n - 2) + \mathsf{msm}(N - 1, \mathbb{G}_1) \\
  = & (4nN + 13 N + n \log^2 n + 8n + 4) ~ \mathbb{F}_{\mathsf{mul}} \\
  & + (2n + 6) ~ \mathsf{polymul}(0, N - 1) + \mathsf{polymul}(0, 2N - 1) + 2~\mathsf{polymul}(0, 2N - 2) +  \mathsf{polymul}(1, 2N - 2) \\
  & + 4 ~ \mathsf{polymul}(N - 1, N - 1) +  \mathsf{polymul}(0, N - n - 2) + n ~ \mathsf{polymul}(0, -1) \\
  & + \sum_{k = 1}^{n} \mathsf{polymul}(N - 2^{k - 1}, N - 1) + \sum_{k = 1}^{n} \mathsf{polymul}(0, 2N - 2^{k - 1} - 1) \\
  & + \mathsf{polydiv}(2N - 1, N) + n ~\mathsf{polydiv}(0, 1) + \mathsf{polydiv}(n, n) + \mathsf{polydiv}(N - 1, n + 1) \\
  & + 3 ~ \mathsf{msm}(N, \mathbb{G}_1) + \mathsf{msm}(N - n - 1, \mathbb{G}_1) + \mathsf{msm}(2N - 1, \mathbb{G}_1) + 2~\mathsf{msm}(N - 1, \mathbb{G}_1)
\end{aligned}
$$

**Verifier's cost:**

$$
\begin{aligned}
  & (2n + 3) ~ \mathbb{F}_{\mathsf{mul}} + (n + 2) ~ \mathbb{F}_{\mathsf{inv}} + \mathsf{EccMul}^{\mathbb{G}_1} \\
  & + 2 ~ \mathbb{F}_{\mathsf{inv}} + (\log N + 4) ~ \mathbb{F}_{\mathsf{mul}} \\
  & + 2(n - 1) ~ \mathbb{F}_{\mathsf{mul}} \\
  & + (n - 1) ~ \mathbb{F}_{\mathsf{mul}} \\
  & + (5n + 6) ~ \mathbb{F}_{\mathsf{mul}} + 9 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 8 ~ \mathsf{EccAdd}^{\mathbb{G}_1} \\
  & + \mathbb{F}_{\mathsf{mul}} + 9 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 8 ~ \mathsf{EccAdd}^{\mathbb{G}_1} + 2 ~ P \\
  = & (11n + 11) ~ \mathbb{F}_{\mathsf{mul}} + (n + 4) ~ \mathbb{F}_{\mathsf{inv}} + 19 ~ \mathsf{EccMul}^{\mathbb{G}_1} + 16 ~ \mathsf{EccAdd}^{\mathbb{G}_1} + 2 ~ P
\end{aligned}
$$

**Proof size:**

$$
(n + 1) \cdot \mathbb{F}_p + 7 ~ \mathbb{G}_1
$$