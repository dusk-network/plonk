This module explains the inner workings of
commitment schemes. 

Commitment schemes
===================

To employ a commitment scheme, is simply to select a value 
from a finite set and commit to the value such that the 
new 'committed' value cannot be changed. 
Commitment schemes are used in cryptography, 
oft in conjuction with zero knowlegde proofs to 
allow a prover to commit to a polynomial, with values
represented by a short reference string. This is 
then used by verifiers to confirm or deny the claims 
made by the orginal committing party. With this process, 
the commitment, which the committer publishes, is bound, 
meaning it cannot be changed. This process is called *binding*. 
Additionally, the prover is able to make this commitment 
without revaling it - this is called *hiding*. After
the commitment has been made, a prover is able to 
reveal the committed message to a verifier so that 
the message can be compared, for consistency, with the 
commitment.


*Generic Example*

In a game of players P and V:

1. \\(P\\) writes down message \\(b\\) on a piece of paper
2. \\(P\\) places the message in a box and locks it using a padlock 
3. \\(P\\) gives the locked box and key to \\(V\\) 

From the above game, it can been that \\(V\\) is able to 
open the box, and see the committed message. \\(P\\) is 
unable to change the value after giving the 
box to \\(V\\), thus the message is *binding*. As \\(V\\) 
is unable to see the commitment prior to opening 
the box, the commitment is also *hiding*. 

Commitment schemes are defined by a \\(P\\) time 
public key *pk* generation algorithm \\(G\\). The 
input is \\(1^{l}\\), where \\({\mathbb l}\\) is the security parameter 
that directly relates to the length of the string. 
There is an outputted *pk*, which is the public key 
of the commitment scheme. In practice, the protocol 
is ran like this:

1. \\(P\\) or \\(V\\) executes \\(G\\) to return *pk*, as a string, 
and sends it to the other party.
2. To make the commitment, the recieving party calculates 
a random *r* from \\(({0,1})^{l}\\) and computes the commitment, 
\\(C\\):

\\[
\begin{aligned}
\operatorname{Commitment}(b,r) 
\end{aligned}
\\]

 
3. The commitment is opened, meaning \\(b\\) & \\(r\\) are revealed and 
\\(V\\) checks that the commitment, \\(C\\), satisfies: 
\\[
\begin{aligned}
\operatorname{Commitment}(b,r) 
\end{aligned}
\\]

The property of having either \\(P\\) *or* \\(V\\) running the 
algorithm affects the type of commitment scheme and the 
satisfied requirements. With respect to the *hiding* and 
*binding* properties, this commitment can be constructed
in two different ways.

When \\(V\\) generates the public key and sends it to \\(P\\), 
then the *binding* is computational and the *hiding* is 
unconditional. The *computational binding* in this commitment 
scheme, means the chance of being able to change the 
commitment is negligible. The *unconditional hiding* 
means that a commitment to b reveals no information about b. 

When \\(P\\) generates the public key and sends it to \\(V\\), then 
the *binding* is unconditional and the *hiding* is computational. 
The *unconditional binding* describes how \\(P\\) is unable to 
change the commitment value after it has been commited to. 
The *computational hiding* means the probability of \\(V\\) being 
able to guess the commitment value is negligible. 


Polynomial commitment schemes can be defined in the following way:



Let \\({\mathbb G}\\) be a group of prime order *p*. 
Let \\({\mathbb g}\\) and \\({\mathbb h}\\) be generators of \\({\mathbb G}\\),
such that:
\\[
\begin{aligned}
{\mathbf{g}}, {\mathbf{h}}  &\in {\mathbb G}
\end{aligned}
\\]

Either \\({\mathbf g}\\) or \\({\mathbf h}\\) are used to produce 
*pk*, which has a commitment appended to it by the committer. 

This commitment is equal to message \\({\mathbb m}\\),
where:
\\[
\begin{aligned} 
{\mathbf{m}}  &\in\ {\mathbb Z\_{p}},
\end{aligned}
\\]

The commitment which is made once these variables are derived, is:

\\[
\begin{aligned}
\operatorname{Commitment}\_{pk}(b,r) = 
{\mathbf{g}^{r}} 
\cdot 
{\mathbf{h}^{b}}
\end{aligned}
\\]



The above equation is generic to using short strings, 
as values, to commit to a polynomial and generate an evaluated 
value. 










