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
given data set which imposes 'n' constrtiants and computes 
an exact fitting solution. 

Linear Algebra dictates that interpolation polynomial ought 
to be formed from the system {\mathbf{A}\{x}} = {\mathbf{b}}, 
where b\_i = y\_i, i\\ = 0,...,n\\, and the entries of {\mathbf{A}} 
are defined by {\mathbf{a}}\_{\operatorname{ij}} = 
{\mathbf{p}}{(x\_i)},i\\,j\\ = 0,....,n, where x\_0,x\_1,...,x\_n 
are the points at which data y\_o, y\_1,...,y\_n are obatained, and 
{\mathbf{p\_j}}{(x\_i)} = x^{j}, j\\ = 0,1,...,n. The basis {1,x\\,...,
x^{n}} of the space of polynomials degree n\\+1 is valled the *monomial 
basis*, and the corresponding matrix A is called the *Vandermode
matrix* for the points x\_0, x\_1,...,x\_n. 

*Langrangian interpolation*, however, has th matrix A as he identity 
matrix. 
This stems from writing the interpolating polynomial as

\begin{aligned}
 {\mathbf{p\_n }}{(x\\)} = \sum_{j=0}^{n} y\_i\mathcal{L}\_n,j{(x)},
 \end{aligned}

where the polynomials {\mathcal{L\_n},\_j(x\_i)} have the property 
that 
\documentclass{article}
\usepackage{amsmath}
\begin{document}
\begin{equation}
  {\mathcal{L\_n},\_j(x\_i)}
    \begin{cases}
      1 & \text{if $i$ = $j$}\\
      0 & \text{if $i$ \neq $j$}\\

    \end{cases}       
\end{equation}
\end{document}
 
 The polynomials {\mathcal{L\_n},\_j}, j\\ = 0,...,n, are intertpolations
 of the points x\_0, x\_1,...,x\_n. Theya are commonly called the 
*Lagrangian polynomials*.
They are wriiten in the form 
\begin{aligned}
 {\mathbf{p\_n }}{(x\\)} = \sum_{j=0}^{n} $f$(x\_j)\mathcal{L}\_n,j
 \end{aligned}

 the unique solution polynomial of degree 'n' that satisfies this 
\begin{aligned}
 {\mathbf{p\_n}}{(x\_j)},i\\,j\\ = $f$(x\_j), $j$ = 0,1,...1,n.
 \end{aligned}

 This polynomial, {\mathbf{p\_n}}{(x\_j)} is called the *interpolating
 polynomial* of $f$(x). 

 
 Example
 ======= 
 
 
 
 
