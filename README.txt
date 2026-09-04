Identify what aspects of the work have been correctly implemented and what have not.

Implemented: all.
Correctly implemented: hopefully all.


Identify anyone with whom you have collaborated or discussed the assignment.

Cristof Inderblitzen re: Nikto scans.


Say approximately how many hours you have spent completing the assignment.

6.


List any additional dependencies used.

N/A.


For this lab, you must also address the following questions:
Are the heuristics used in this assignment to determine incidents "even that good"?

I would say no. At least in my implementation, I detect incidents using specific criteria 
that fits one type of detection for each possible incident; it is highly possible that 
incidents could be detectable via a variety of methods rather than a one size fits all 
type of methodology.


If you have spare time in the future, what would you add to the program or do differently 
with regards to detecting incidents?

I would explore a variety of methods of detection for each incident type and do more thorough 
research on how each incident type is noticeable in network traffic.


Use of AI:

At first, I was confused on the form of data that the "packet" parameter is represented as. 
My prompt: "Could you provide an example of using scapy with python to detect a NULL scan?"

I was stuck on how to extract the credentials from the network traffic, as well as the difference 
in extraction methods for each protocol.
My prompt: "Could you provide an example of using scapy with python to extract credentials 
from HTTP Basic Authorization, IMAP, and FTP from network traffic?"

For SMP, RDP, and VNC, I wasn't sure what ports to scan for.
My prompt: "When using scapy with python to detect [incident], which source and destination 
ports should I be investigating?"
