In this module we show how and why the KZG10 
polynomial commitment scheme has been modularised 
for this PLONK implementation.

KZG10 Commitments 
==================

PLONK can be constructed with different 
commitment schemes and does not requre solely
homomorphic commitments. However, this library
has only homomorphic commitment schemes as they 
are intelligble for users and have many useful
properties.

We use 'KZG10 commitments', often called 'Kate' 
commitments refers to the commitments scheme 
created by Kate, Zaverucha and Goldberg. 
There a multiple benefits of the KZG10 commitments
aside from having readable code. It allow us to have 
constant size commitments, which is achieved by having
the commitments as single elements. The cost of these 
commitments is also constant irrespective of the 
number of evaluations, so we are able to work with a 
low overhead cost.

A deep explanation on how this particular commitment 
scheme operates can be found [here][https://pdfs.semantics
cholar.org/31eb/add7a0109a584cfbf94b3afaa3c117c78c91.pdf] 
in the original paper.


This commitment is used to build the structured 
reference string (SRS), and commit to a polynomial
\phi by means of a bilinear pairing group.
Where {\mathbf{G_1}} and {\mathbf{G_2}} and groups 
two different pairing curves with generators {\mathbf{G}}
&\in {\mathbf{G_1}} and {\mathbf{G}} &\in {\mathbf{G_2}}, 
respectively. 

These commitments are homomorphic, which enables us 
to perform operations on the already encryptied values 
and have the evaluation be indistinguishable from the 
evaluation of operations performed on the decrypted values.
In terms of Kate commitments, we are able to take two
commitment messages {\mathbf{m_1}} and {\mathbf{m_2}}, 
and know there is a an efficient product operation 
for them both which equates to a commitment 
 {\mathbf{m_1}}, {\mathbf{m_2}}.
i.e.
\begin{aligned}
\C{\mathbf{m_1}} \cdot \C{\mathbf{m_2}} \equiv 
\C({\mathbf{m_1}} \bigotimes {\mathbf{m_2}})
\end{aligned}
