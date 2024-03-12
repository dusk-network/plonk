# Zero-Knowledge Proofs

In the following article, you will learn about Zero-Knowledge Proofs, understand what they imply, and ultimately learn about different Zero-Knowledge Proof constructions.

## Definition

A Zero-Knowledge Proof (ZKP) \[[1](#1)\] is a cryptographic primitive which allows a proving party $P$ to convince a verifying party $V$ that a statement is true, without leaking any secret information. A statement $u$ is a set of elements known by both parties, and the secret information only known by $P$ is the witness $w$. Formally speaking, ZKPs must satisfy 3 properties:

- **Completeness:** If the statement is true, $P$ must be able to convince $V$.
- **Soundness** If the statement is false, $P$ must not be able to convince $V$ that the statement is true, except with negligible probability.
- **Zero-Knowledge** $V$ must not learn any information from the proof beyond the fact that the statement is true.

## Example
To understand what the above definition means, let us look at an example.

Consider the graph [coloring problem][graph coloring]. You have a graph of vertices connected by edges. Every edge connects to two vertices and every vertex can be connected to any number of edges.  Now you get three colors and need to color each vertex in such a way, that no edge connects to two vertices of the same color. Not all graphs have a valid solution to this problem and it happens that while it is easy to construct a graph with a valid solution, it is not easy at all to determine *if* a given graph has a valid solution or *how* that solution might look like.

<p align=center>
<img src="https://upload.wikimedia.org/wikipedia/commons/c/c2/Triangulation_3-coloring.svg" alt="drawing" width="35%"/>
</p>

Let's say that we show you a sufficiently big, uncolored graph and tell you that we know a way to color the vertices as described above but we want to keep the solution secret. How can we prove to you that we indeed know a valid solution without sharing any information about the solution itself?

First we hide the graph from you and color each vertex in one of three colors according to our solution. Then we cover each vertex with a sticker and show you the graph with the stickers. You now see the same graph and each vertex is covered with a sticker. You are not able to make any assumptions regarding our solution. Next we ask you to pick a random edge. The two vertices connected to that edge should have different colors. We peel off the stickers and show you that indeed the two vertices are of different color. At this point of course, you will not be convinced yet that our solution is valid, after all we might just have been lucky. So we take another copy of the graph and we repeat the process but each run we use a different random distribution of the three colors to color the vertices. We will repeat this process will until the chances of me being lucky become so small that you are convinced.

If we look at the above definition of ZKPs, we can see:
- Our example is **complete**: If we have a valid solution, we will be able to convince you.
- Our example is **sound**: If we don't have a valid solution, we will not be able to convince you.
- Our example reveals **zero-knowledge**: Because the colors are reshuffled in every run, you can not draw any conclusions about our solution.

## Key Concepts

Conventional proof systems make sure that $P$ cannot act maliciously. ZKP systems take this a step further, and also make sure that $V$ cannot act maliciously. After computing and sending a ZKP, $V$ (or an eavesdropper) only learns that $P$ is in possession of $w$, nothing more. This fact has the following implications:

- $V$ is not able to prove to a third party that they know $w$ (because they do not know it). 
- $V$ is not able to prove to a third party that the initial $P$ knows $w$.

The second point might sound a bit strange at first, so let us look at it in more detail:

Say you recorded the proving procedure of the coloring problem explained above, so you can later convince your very skeptical friends that we know a valid solution. On the recording they would see that every edge you chose indeed connects two vertices of different color. But it won't convince them (they are very skeptical) since you and us could have played false and agreed on the vertices to be uncovered beforehand.

So, where do we want to go with it? Using ZKPs you would, for example, be able to prove that you know a password without ever giving it to any potentially malicious third party or eavesdropper. As such, you could prove your identity to just one person and he would not be able to prove that to anyone else, nor impersonate you.  

In the context of Blockchains, where data about transactions between parties is publicly stored in a shared ledger between members of the network, ZKPs can become a useful approach to integrate: you could prove that a transaction is valid without revealing any information about the transaction itself, thus guaranteeing your privacy. But... having to play the coloring procedure again with every member of the network is not efficient at all. Here is where a new term comes to the playground: *Non-interactive ZKPs* (NIZKPs).

Now, using NIZKPs, instead of having to exchange multiple messages between $P$ and $V$, the former is able to prove knowledge of $w$ by sending just a single message. This is possible thanks to different approaches, like agreeing on a *Common Reference String* (CRS) \[[2](#2)\], or using the Fiat-Shamir heuristic \[[3](#3)\].

We can see our NIZKP system as a blackbox with two sets of inputs, the statement $u$ being a set of public intputs, and the witness $w$ the set of private inputs. Such a blackbox generates a proof $\pi$ that $V$ will verify, as depicted here:
<p align=center>
<img src="https://github.com/dusk-network/plonk/blob/docs/docs/images/zkp.png?raw=true" width="50%"/>
</p>

## ZKP constructions

Over time, different ZKP constructions have been designed. They have beautiful names like *STARK* (Scalable Transparent ARgument of Knowledge), *Bulletproof*, *SNARG* (Succinct Non-interactive ARGuments) and *SNARK* (Succinct Non-interactive ARgument of Knowledge). We will not explain the different protocols in detail here. Instead, we will just give a brief overview of what those fancy abbreviations actually mean so you have a starting point for the next internet research rabbit hole.

- **Scalable:**  Both $P$ and $V$ running times are scalable.
- **Transparent:** Doesn't require a setup-phase which uses a non-public random parameter like the CRS mentioned above.
- **Argument:** Strictly mathematically speaking, many of the above protocols are no proofs but arguments. However in practice we can still think of them as a proofs.
- **Knowledge:** $P$ proves to $V$ that they themselves know the solution. In our above example that means that $P$ doesn't prove that a solution exists but that they actually know the solution.
- **Succinct:** The proofs are relatively small and easy to verify.
- **Non-interactive:** No interaction between $P$ and $V$ is needed.


[graph coloring]: https://en.wikipedia.org/wiki/Graph_coloring#Vertex_coloring

## References
<a id="1">\[1\]</a> 
Goldwasser, S.; Micali, S.; Rackoff, C. "The knowledge complexity of interactive proof-systems". In Proceedings of the Seventeenth Annual ACM Symposium on Theory of Computing, Providence, RI, USA, 6–8 May 1985; ACM: New York, NY, USA, 1985; pp. 291–304.

<a id="2">\[2\]</a> 
Groth K.; Kohlweiss M.; Maller M.; Meiklejohn S.; Miers I. "Updatable and Universal Common Reference Strings with Applications to zk-SNARKs". Cryptology ePrint Archive, Report 2018/280.

<a id="3">\[3\]</a> 
Fiat, A.; Shamir, A. "How To Prove Yourself: Practical Solutions to Identification and Signature Problems", Advances in Cryptology --- CRYPTO' 86", 1987.