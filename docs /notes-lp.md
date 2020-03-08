The notes within this module explain the inner workings
of Lagrangian polynomials.

Langrangian polynomials
=======================

Langrangian polynomials are introduced as a means of 
constructing continuos functions from discrete data.
With alternative polynomial constructions, discrete 
data sets can be approximated; Langrangian polynomials, 
however, from a solution that fits data exactly. This is 
achieved through *interpolation*, which finds a linear 
combination of 'n' inputted functions with respect to a 
given data set which imposes 'n ' constrtiants and computes 
an exact fitting solution. 

Linear Algebra dictates that interpolation polynomial ought 
to be formed from the system {\mathbf{A}\{x}} = {\mathbf{b}}, 
where b\_i = y\_i, i\\ = 0,...,n\\, and the entries of {\mathbf{A}} 
are defined by {\mathbf{a}}\_{\operatorname{ij}} = 
{\mathbf{p}}{(x\_i)},i\\,



 The most straightforward method of computing the interpolation polynomial is to form the
system 퐴x = b where 푏푖 = 푦푖
, 푖 = 0, . . . , 푛, and the entries of 퐴 are defined by 푎푖푗 = 푝푗 (푥푖),
푖, 푗 = 0, . . . , 푛, where 푥0, 푥1, . . . , 푥푛 are the points at which the data 푦0, 푦1, . . . , 푦푛 are obtained, and
푝푗 (푥) = 푥
푗
, 푗 = 0, 1, . . . , 푛. The basis {1, 푥, . . . , 푥푛} of the space of polynomials of degree 푛 + 1
is called the monomial basis, and the corresponding matrix 퐴 is called the Vandermonde matrix
1
for the points 푥0, 푥1, . . . , 푥푛. Unfortunately, this matrix can be ill-conditioned, especially when
interpolation points are close together.
In Lagrange interpolation, the matrix 퐴 is simply the identity matrix, by virtue of the fact that
the interpolating polynomial is written in the form