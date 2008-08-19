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


Developer notes
===============

*Module Dependencies Layers*
----------------------------

jSPF source code is structured in 4 layers. The topmost layer is the org.apache.james.jspf.impl
package and it depends on every other package in the sources.

Then we have a second layer including the "executor" package, the "policy"+"policy.local" packages, 
the "parser" package and the "wiring" package. "executor", having no dependencies in the third 
layer could be included in both the second and the third layer. "wiring" does not have dependencies.

The third layer includes only the "terms" package. It depends on "core" (the fourth layer).

The fourth layer includes "core"+"core.exceptions" packages. They have no dependencies on other
packages. Instead every other package depends on this code.

*Mixed Synchronous/Asynchronous Implementation*
-----------------------------------------------

jSPF born as a synchronous implementation, but soon introduced asynchronous support via dnsjnio
asynchronous dns resolver library. The "Continuation" pattern has been used to support asynchronous
operations.

The whole processing is defined by "SPFChecker"s. An SPFChecker is an object that takes an SPFSession and 
applies the needed transformations. Whenever a DNS lookup is needed an SPFChecker is allowed to return 
a DNSLookupContinuation. A DNSLookupContinuation simply tells the executor that a given DNSRequest should  
be resolved and the DNSResponse should be returned to the given SPFCheckerDNSResponseListener (that in  
turn is allowed to return DNSLookupContinuation if it needs DNS lookups). When an SPFChecker (or the 
SPFCheckerDNSResponseListener) completed the processing it will return null.

The SPFSession includes a checkers stack: A checker can also implement the SPFCheckerExceptionCatcher
interface to be able to intercept exceptions from the nested checkers.
The SPFExecutor role is to pop an SPFChecker from the SPFSession and execute it, by processing the
DNSRequests included in the returned DNSLookupContinuations until a null is returned. If an exception
is thrown by the current checker then the executor will poll every checker from the stack looking for
a checker implementing the SPFCheckerExceptionCatcher interface, will remove it from the stack and
will execute its onException method to handle the exception.
Please note that the SPFCheckerExceptionCatcher call wil often result in an additional exception to be
rethrown and the executor will take care to pop the chekers looking for another catcher that will handle
the new exception.

Terms, Policies and the Parser are all implementations of the SPFChecker interface. An SPFChecker
implementation can do every processing in the checkSPF method or can simply push more fine grained
SPFCheckers to the checkers Stack in the SPFSession.

*Packages*
----------

core: includes the core classes for the jSPF library.

wiring: an utility package used to "wire" components for the runtime. It has no dependencies.

terms: depends on core and defines basic Mechanism and Modifiers (Directive) terms. The terms simply
  implements one of the Mechanism / Modifier interfaces and contain a static property to define
  the regular expression used to parse the term from the record. 

parser: the RFC4408SPF1Parser is the core class and it creates an SPF1Record by parsing the spf record.
  the "grammar" is automatically created by reading the jspf.default.terms file that define the known
  Modifiers and the known Mechanisms. At startup every modifier/mechanism is analyzed and a big
  regexp is built to parse the records. Every time a record is parser the TermsFactory is used to
  obtain a Service-Wired instance of the term.

executor: an SPFExecutor (defined in the core package) is an object that process an SPFSession and 
  returns an SPFResult (when asynchronous executors are used the SPFResult returned will be a 
  FutureSPFResult). The executor 

---------------------
The Apache James team
