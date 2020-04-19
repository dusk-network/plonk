In this module we show how and why the KZG10 
polynomial commitment scheme has been implemented
for this PLONK implementation.

KZG10 Commitments 
==================

PLONK can be constructed with different 
commitment schemes and does not requre solely
homomorphic commitments. However, this library
implemnts only homomorphic commitments for two 
reasons. One is their useful properties when 
given encrypted values, and the second is the 
requirements of the linearisation technique in
PLONK.

PLONK makes use of the linearisation technique, 
originally conceived in the SONIC [paper][sonic_paper]. 
This technique requires the 
the commitment scheme to be homomorphic. 
The use of this lineariser in the PLONK 
protocol prevents us from being able to 
use merkle tree like techniques, such as 
the [FRI][fri_paper] protocol. 
 


We use 'KZG10 commitments', often called 'Kate' 
commitments refers to the commitments scheme 
created by Kate, Zaverucha and Goldberg. 
A deep explanation on how this particular commitment 
scheme operates can be found [here][kzg10_paper] 
in the original paper.
Aside from the compatability wiht the chosen 
linearisation technique, there are multiple 
benefits of using the KZG10 commitment scheme
in the PLONK. The first is that it allow
us to have constant size commitments; the witness 
of the evaluations is a single group element. 
The cost of these commitments is also constant 
irrespective of the number of evaluations, 
so we are able to employ with a low overhead cost.





This commitment is used to commit to a polynomial,
from a given structured reference string (SRS),
\phi by means of a bilinear pairing group.
Where {\mathbf{G_1}} and {\mathbf{G_2}} and groups 
two different pairing curves with generators {\mathbf{G}}
&\in {\mathbf{G_1}} and {\mathbf{G}} &\in {\mathbf{G_2}}, 
respectively. 

These commitments are homomorphic, which enables us 
to perform operations on the already encrypted values 
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




[sonic_paper]:https://eprint.iacr.org/2019/099.pdf
[fri_paper]:https://drops.dagstuhl.de/opus/volltexte/2018/9018/pdf/LIPIcs-ICALP-2018-14.pdf
[kzg10_paper]:https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf