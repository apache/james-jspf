Welcome to Apache James jSPF
============================

Apache James jSPF is an Apache 2.0 licensed java library that implements the SPF specification.

There are 2 main entry points to the library:
1) The SPFQuery command line tool
2) The SPF class, for programmatic use


SPFQuery
--------
You need jspf library, dnsjava and log4j libraries in your classpath, then you run
> java -jar jspf-version.jar
to get the usage.


SPF
---
Here is a simple usage of the library:

DefaultSPF spf = new DefaultSPF();
SPFResult res = spf.checkSPF("192.168.0.1", "from@example.com", "example.com");
if (res.getResult().equals(SPF1Utils.FAIL_CONV)) {
 ... do something ...
} else if (res.getResult().equals(SPF1Utils.PASS_CONV)) {
 ... something else..
} else .....
Further results are:

PERM_ERROR_CONV = "error";
NONE_CONV = "none";
TEMP_ERROR_CONV = "temperror";
PASS_CONV = "pass";
NEUTRAL_CONV = "neutral";
FAIL_CONV = "fail";
SOFTFAIL_CONV = "softfail";


Links
-----
http://www.openspf.org/ for the latest informations about SPF
http://james.apache.org/jspf/ for the jSPF website, javadocs, xdocs and more.


Please help us make jSPF better - we appreciate any feedback you may have.
Enjoy!

---------------------
The Apache James team
