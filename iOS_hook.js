function replace_func_void(func_address) {
    var custom = module_base.add(func_address);
    Interceptor.replace(custom, new NativeCallback(function () {
        console.log();
        console.warn("[*] ", func_address, " Bypass void");
        console.log("-----------------------------------------------------------------------------------");
    }, 'void', []));
}

function replace_func_bool(func_address, vlaue) {
    var custom = module_base.add(func_address);
    Interceptor.replace(custom, new NativeCallback(function () {
        console.log();
        console.warn("[*] ", func_address, " Bypass ", vlaue);
        console.log("-----------------------------------------------------------------------------------");
        return vlaue
    }, 'bool', []));
}

function NSFileManager_Hook() {
    for (var className in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(className)) {
            if (className == "NSFileManager") {
                send("Found target class : " + className);

                var hook = ObjC.classes.NSFileManager["- createFileAtPath:contents:attributes:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        send("[+][NSFileManager] create File at: " + obj.toString());

                        var obj = ObjC.Object(args[3]);
                        var string = ObjC.classes.NSString.alloc();
                        send("\t- Content : " + string.initWithData_encoding_(obj, 4));

                        var obj = ObjC.Object(args[4]);
                        send("\t- Attributes : " + obj.toString());
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                    }
                });
                var hook = ObjC.classes.NSFileManager["- copyItemAtPath:toPath:error:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] copy File at: " + obj.toString());

                        var obj = ObjC.Object(args[3]);
                        send("\t- To Path : " + obj.toString());
                    }
                });
                var hook = ObjC.classes.NSFileManager["- moveItemAtPath:toPath:error:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] move File at: " + obj.toString());

                        var obj = ObjC.Object(args[3]);
                        send("\t- To Path : " + obj.toString());
                    }
                });
                var hook = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] File Exists at Path: " + obj.toString());
                    }
                });
                var hook = ObjC.classes.NSFileManager["- isReadableFileAtPath:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] File Path: " + obj.toString());
                    },
                    onExit: function (retval) {
                        send("- isReadable? " + retval.toString());
                    }
                });
                var hook = ObjC.classes.NSFileManager["- isWritableFileAtPath:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] File Path: " + obj.toString());
                    },
                    onExit: function (retval) {
                        send("- isWritable? " + retval.toString());
                    }
                });
                var hook = ObjC.classes.NSFileManager["- isExecutableFileAtPath:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] File Path: " + obj.toString());
                    },
                    onExit: function (retval) {
                        send("- isExecutable? " + retval.toString());
                    }
                });
                var hook = ObjC.classes.NSFileManager["- isDeletableFileAtPath:"];
                Interceptor.attach(hook.implementation, {
                    onEnter: function (args) {
                        var obj = ObjC.Object(args[2]);
                        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
                        send("[+][NSFileManager] File Path: " + obj.toString());
                    },
                    onExit: function (retval) {
                        send("- isDeletable? " + retval.toString());
                    }
                });
            }
        }
    }
}

function print_buf(address, size) {
    var buf = Memory.readByteArray(address, size);
    console.log("\n", hexdump(buf, {
        offset: 0,
        length: size,
        header: true,
        ansi: false
    }));
}

function exit_trace() {
    var exit = Module.findExportByName('libSystem.B.dylib', 'exit');
    Interceptor.attach(exit, {
        onEnter: function (args) {
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
            console.log("[*] exit Call");
        },
        onLeave: function (retval) {
        }
    });
}

function show_original(func_address) {
    var custom = module_base.add(func_address);
    Interceptor.attach(custom, {
        onEnter: function (args) {
            //console.log("############# ", func_address, " show original value #############");
            //console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
        },
        onLeave: function (retval) {
            console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
            console.log("Return : ", ObjC.Object(retval).toString());
            //console.log("Return Type : ", typeof (retval));
            //console.log("Return To String : ", Memory.readCString(retval));
            //console.log("Return Register : ", JSON.stringify(this.context))
        }
    });
}

function print_equal_string() {
    Interceptor.attach(ObjC.classes.NSString['+ stringWithUTF8String:'].implementation, {
        onEnter: function (args) {
            console.log('[+] Hooked +[NSString stringWithUTF8String:] ');
        },
        onLeave: function (retval) {
            var str = new ObjC.Object(ptr(retval)).toString()
            console.log('[+] Returning [NSString stringWithUTF8String:] -> ', str);
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
            return retval;
        }
    });

    Interceptor.attach(ObjC.classes.__NSCFString['- isEqualToString:'].implementation, {
        onEnter: function (args) {
            var str = new ObjC.Object(ptr(args[2])).toString()
            console.log('[+] Hooked __NSCFString[- isEqualToString:] -> ', str);
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
        }
    });

    Interceptor.attach(ObjC.classes.NSTaggedPointerString['- isEqualToString:'].implementation, {
        onEnter: function (args) {
            var str = new ObjC.Object(ptr(args[2])).toString()
            console.log('[+] Hooked NSTaggedPointerString[- isEqualToString:] -> ', str);
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
        }
    });
}

function openALL() {
    Interceptor.attach(Module.findExportByName(null, "fopen"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            console.log("[+] Fopen ARG[0] : " + path);
        }
    });

    Interceptor.attach(Module.findExportByName(null, "open"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = Memory.readUtf8String(args[0]);
            console.log("[+] Open ARG[0] : " + path);
        }
    })
}

function trace_function() {
    function trace(pattern) {
        var type = (pattern.indexOf(" ") === -1) ? "module" : "objc";
        var res = new ApiResolver(type);
        var matches = res.enumerateMatchesSync(pattern);
        var targets = uniqBy(matches, JSON.stringify);

        targets.forEach(function (target) {
            if (type === "objc")
                traceObjC(target.address, target.name);
            else if (type === "module")
                traceModule(target.address, target.name);
        });
    }

    // remove duplicates from array
    function uniqBy(array, key) {
        var seen = {};
        return array.filter(function (item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }

    // trace ObjC methods
    function traceObjC(impl, name) {
        console.log("Tracing " + name);

        Interceptor.attach(impl, {

            onEnter: function (args) {

                // debug only the intended calls
                this.flag = 0;
                // if (ObjC.Object(args[2]).toString() === "1234567890abcdef1234567890abcdef12345678")
                this.flag = 1;

                if (this.flag) {
                    console.warn("\n*** entered " + name);

                    // print full backtrace
                    // console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    //		.map(DebugSymbol.fromAddress).join("\n"));

                    // print caller
                    console.log("\nCaller: " + DebugSymbol.fromAddress(this.returnAddress));

                    // print args
                    if (name.indexOf(":") !== -1) {
                        console.log();
                        var par = name.split(":");
                        par[0] = par[0].split(" ")[1];
                        for (var i = 0; i < par.length - 1; i++)
                            printArg(par[i] + ": ", args[i + 2]);
                    }
                }
            },

            onLeave: function (retval) {

                if (this.flag) {
                    // print retval
                    printArg("\nretval1: ", retval);
                    console.warn("\n*** exiting1 " + name);
                }
            }

        });
    }

    // trace Module functions
    function traceModule(impl, name) {
        console.log("Tracing " + name);

        Interceptor.attach(impl, {

            onEnter: function (args) {

                // debug only the intended calls
                this.flag = 0;
                // var filename = Memory.readCString(ptr(args[0]));
                // if (filename.indexOf("Bundle") === -1 && filename.indexOf("Cache") === -1) // exclusion list
                // if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
                this.flag = 1;

                if (this.flag) {
                    console.warn("\n*** entered " + name);

                    // print backtrace
                    console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            },

            onLeave: function (retval) {

                if (this.flag) {
                    // print retval
                    printArg("\nretval2: ", retval);
                    console.warn("\n*** exiting2 " + name);
                }
            }

        });
    }

    // print helper
    function printArg(desc, arg) {
        try {
            console.log(desc + ObjC.Object(arg));
        }
        catch (err) {
            console.log(desc + arg);
        }
    }

    // usage examples
    if (ObjC.available) {
        //trace("*[* *resultCode*]");
        //trace("*[NSString stringWithCString:encoding:]");
        //trace("*[e2PXh02d onError:param:resultCode:]");
        //trace("*[x9J5Y7iA applicationDidBecomeActive:]");
        //trace("*[u9prwT9U *]")
        //trace("*[x9J5Y7iA *]")
        //trace("*[* initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:]");
        //trace("*[u9prwT9U *]");
        //trace("*[BAAlertView *]");
        //trace("*[* stringWithUTF8String*]");
        //trace("-[i2SGbxV4 m96Z6OY6:]");
        //trace("*[* localizedStringForKey:value:table:]");
        //trace("*[SDWeakProxy *]");
        //trace("*[NSString stringWithCString:encoding:]");
        //trace("*[w50U9iiS *]");
        //trace("*[EN_AIP *]");
        //trace("*[AMSLBouncer doCipher:key:context:padding:]")
        //trace("-[TLFConnectionMessage initWithConnection:request:response:error:]")
        //trace("*[ams2Library *]")
        //trace("-[TLFControlMessage initWithViewButtonClick:view:andUIAlertController:]")
        //trace("*[UIAlertController alertControllerWithTitle:message:preferredStyle:]")
        //trace("*[* contentViewController]")
        //trace("*[* *alertController*]")
        //trace("*[* *printWithTitle*]")
        //trace("*[LPMain2020ViewController *popupToast*]")
        //trace("*[LPAppAuthListViewController *]")
        //trace("*[UIAlertAction title]")
        //trace("*[LPAppDelegate showErrorArxanPopup:]")
        //trace("*[*alertController* *]")
        //trace("-[LPFirstAlertViewController  *]")
        //trace("-[LPAppDelegate showErrorArxanPopup:]")
        //trace("*[* alert:title:leftBtn:rightBtn:centerBtn:contentView:url:handler:]")
        //trace("*[NHCAlert *]")
        //trace("*[kCFNetworkProxiesHTTPEnable *]")
        //trace("*[* kCFNetworkProxiesHTTPEnable]")
        trace("*[NSString stringWithCString:encoding:]")

    } else {
        send("error: Objective-C Runtime is not available!");
    }
}

function jailbreak_detect_trace() {
    function logtrace(ctx) {
        var content = Thread.backtrace(ctx.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n';
        if (content.indexOf('SubstrateLoader') == -1 && content.indexOf('JavaScriptCore') == -1 &&
            content.indexOf('FLEXing.dylib') == -1 && content.indexOf('NSResolveSymlinksInPathUsingCache') == -1 &&
            content.indexOf('MediaServices') == -1 && content.indexOf('bundleWithPath') == -1 &&
            content.indexOf('CoreMotion') == -1 && content.indexOf('infoDictionary') == -1 &&
            content.indexOf('objectForInfoDictionaryKey') == -1) {
            console.log(content);
            return true;
        }
        return false;
    }

    function iswhite(path) {
        if (path == null) return true;
        if (path.startsWith('/var/mobile/Containers')) return true;
        if (path.startsWith('/var/containers')) return true;
        if (path.startsWith('/var/mobile/Library')) return true;
        if (path.startsWith('/var/db')) return true;
        if (path.startsWith('/private/var/mobile')) return true;
        if (path.startsWith('/private/var/containers')) return true;
        if (path.startsWith('/private/var/mobile/Library')) return true;
        if (path.startsWith('/private/var/db')) return true;
        if (path.startsWith('/System')) return true;
        if (path.startsWith('/Library/Preferences')) return true;
        if (path.startsWith('/Library/Managed')) return true;
        if (path.startsWith('/usr')) return true;
        if (path.startsWith('/dev')) return true;
        if (path == '/AppleInternal') return true;
        if (path == '/etc/hosts') return true;
        if (path == '/Library') return true;
        if (path == '/var') return true;
        if (path == '/private/var') return true;
        if (path == '/private') return true;
        if (path == '/') return true;
        if (path == '/var/mobile') return true;
        if (path.indexOf('/containers/Bundle/Application') != -1) return true;
        return false;
    }

    Interceptor.attach(Module.findExportByName(null, "access"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            console.log("access " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "chdir"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (!iswhite(path)) console.log("chdir " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "chflags"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (!iswhite(path)) console.log("chflags " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "connect"), {
        onEnter: function (args) {
            var port = Memory.readUShort(args[1].add(2));
            port = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
            if (port == 22 || port == 27042) {
                console.log("connect " + port);
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "creat"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("creat " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (!iswhite(path)) console.log("dlopen " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "dlopen_preflight"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (!iswhite(path)) console.log("dlopen_preflight " + path);
        }
    })

    var dyld_get_image_name_show = false;
    Interceptor.attach(Module.findExportByName(null, "_dyld_get_image_name"), {
        onEnter: function (args) {
            if (!dyld_get_image_name_show) {
                if (logtrace(this)) {
                    console.log("dyld_get_image_name");
                    dyld_get_image_name_show = true;
                }
            }
        }
    })


    Interceptor.attach(Module.findExportByName(null, "execve"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            console.log("execve " + Memory.readUtf8String(args[0]));
        }
    })

    Interceptor.attach(Module.findExportByName(null, "fork"), {
        onEnter: function (args) {
            console.log("fork");
        }
    })

    Interceptor.attach(Module.findExportByName(null, "getenv"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var envname = Memory.readUtf8String(args[0]);
            if (envname == 'DYLD_INSERT_LIBRARIES' || envname == 'MSSafeMode') {
                if (logtrace(this)) console.log(content);
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "getxattr"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("getxattr " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "link"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("link " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "listxattr"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("listxattr " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "lstat"), {
        block: false,
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("lstat " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "open"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = Memory.readUtf8String(args[0]);
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("open " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "opendir"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("opendir " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "__opendir2"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("opendir2 " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "popen"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (!iswhite(path)) console.log("popen " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onEnter: function (args) {
            console.log("ptrace");
        }
    })

    Interceptor.attach(Module.findExportByName(null, "readlink"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("readlink " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "realpath"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("realpath " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "realpath$DARWIN_EXTSN"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("realpath$DARWIN_EXTSN " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "stat"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("stat " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "statfs"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("statfs " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "symlink"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var path = args[0].readUtf8String();
            if (iswhite(path)) return;
            if (logtrace(this)) console.log("symlink " + path);
        }
    })

    Interceptor.attach(Module.findExportByName(null, "syscall"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            var callnum = args[0].toInt32();
            if (callnum == 180) return;
            console.log("syscall " + args[0].toInt32());
            if (callnum == 5) {
                console.log('syscall open ' + args[8].readUtf8String());
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "system"), {
        onEnter: function (args) {
            if (args[0].isNull()) return;
            console.log("system " + Memory.readUtf8String(args[0]));
        }
    })

    Interceptor.attach(Module.findExportByName(null, "task_for_pid"), {
        onEnter: function (args) {
            console.log("task_for_pid");
        }
    })

    var LSCanOpenURLManager = ObjC.classes._LSCanOpenURLManager;
    var NSFileManager = ObjC.classes.NSFileManager;
    var UIApplication = ObjC.classes.UIApplication;

    Interceptor.attach(LSCanOpenURLManager["- canOpenURL:publicSchemes:privateSchemes:XPCConnection:error:"].implementation, {
        onEnter: function (args) {
            var path = ObjC.Object(args[2]).toString();
            if (path.startsWith('cydia') || path.startsWith('Cydia'))
                console.log("LSCanOpenURLManager canOpenURL:publicSchemes:privateSchemes:XPCConnection:error: " + path);
        }
    })

    Interceptor.attach(UIApplication["- canOpenURL:"].implementation, {
        onEnter: function (args) {
            var path = ObjC.Object(args[2]).toString();
            if (path.startsWith('cydia') || path.startsWith('Cydia'))
                console.log("UIApplication canOpenURL: " + path);
        }
    })

    Interceptor.attach(UIApplication["- openURL:"].implementation, {
        onEnter: function (args) {
            console.log("UIApplication openURL: " + ObjC.Object(args[2]).toString());
        }
    })

    Interceptor.attach(Module.findExportByName(null, "__libc_do_syscall"), {
        onEnter: function (args) {
            var callnum = args[0].toInt32() - 233;
            if (false) {
            } else if (callnum == 3) {
                // read
            } else if (callnum == 5) {
                console.log('open ' + args[8].readUtf8String());
            } else if (callnum == 6) {
                // close
            } else if (callnum == 20) {
                // getpid
            } else if (callnum == 39) {
                // getppid
            } else if (callnum == 202) {
                // sysctl
            } else if (callnum == 294) {
                // shared_region_check_np
            } else if (callnum == 340) {
                console.log('stat64 ' + args[8].readUtf8String());
            } else if (callnum == 344) {
                // getdirentries64
            } else {
                console.log('__libc_do_syscall() ' + callnum);
            }
        }
    });
}

function sleep_hook(nativefunc) {
    var nativefunc_addr = Module.getExportByName(null, nativefunc)
    var func = ptr(nativefunc_addr);
    Interceptor.attach(func, { // set hook 
        onEnter: function (args) {
            console.warn("\n[+] " + nativefunc + " called"); // before call 
            if (nativefunc == "sleep") {
                // 4번째 sleep 함수 호출시 인자 바꿔치기 
                if (args[0] == 0xf) {
                    args[0] = ptr(0x1e13380); // 1년 동안 sleep 
                }
                console.log("\n\x1b[31margs[0]:\x1b[0m \x1b[34m" + args[0] + ", \x1b[32mType: ");
            }
        },
        onLeave: function (retval) {
            if (nativefunc == "sleep") {
                console.warn("[-] " + nativefunc + " ret: " + retval.toString()); // after call 
            }
        }
    });
}

function find_module() {
    Process.enumerateModulesSync()
        .filter(function (m) { return m['path'].toLowerCase().indexOf('.app') != -1; })
        .forEach(function (m) {
            console.log(JSON.stringify(m, null, '  '));
            // to list exports use Module.enumerateExportsSync(m.name)
        });

    function infoImportsFunction(moduleName, importPattern) {
        Module.enumerateImportsSync(moduleName)
            .forEach(function (m) {
                if (m.name.match(importPattern)) {
                    console.log(JSON.stringify(m, null, ' '));
                }
            })
    }
}

function Touch_bypass() {
    // LAContext클래스의 evaluatePolicy:localizedReason:reply: 메서드를 이용하여 TouchID기능 구현
    var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function (args) {
            // args[4] 인자값이 block 인지 여부 확인
            console.log("\n\x1b[31margs[4]: \x1b[32m" + ObjC.Object(args[4]) + "\x1b[0m");
            // block 구문 후킹
            var block = new ObjC.Block(args[4]);
            const appCallback = block.implementation;
            block.implementation = function (success, error) {
                // block 구문의 인자값 관찰
                console.log("\n\x1b[31msuccess: \x1b[32m" + success + "\n\x1b[31merror: \x1b[32m" + error + "\x1b[0m");
                // block 구문의 반환값 변경
                const result = appCallback(true, null);
                return result;
            };
        },
    })
}

function print_svc(pattern, func_address, func_size) {
    var m = Process.findModuleByName(BaseAddress)
    Memory.scan(m.base.add(func_address), func_size, pattern, {
        onMatch: function (address, size) {
            console.log();
            console.log(func_address, ' svc 0x80 print');
            console.log("Original : \n", Memory.readByteArray(address, size));
        },
        onComplete: function () {
            //console.log('Memory.scan() complete');
        }
    })
}

function svc_hook(pattern, func_address, func_size) {
    var m = Process.findModuleByName(BaseAddress)
    Memory.scan(m.base.add(func_address), func_size, pattern, {
        onMatch: function (address, size) {
            console.log();
            console.log(func_address, ' svc 0x80 hook!');
            console.log("Original : \n", Memory.readByteArray(address, size));

            Memory.protect(address, size, 'rwx');
            Memory.writeByteArray(address.add(4), [0x1F, 0x20, 0x03, 0xD5]); // NOP 으로 변경
            console.log();
            console.warn("Patch : \n", Memory.readByteArray(address, size));
        },
        onComplete: function () {
            //console.log('Memory.scan() complete');
        }
    })
}

function InitFunc(){
    replace_func_void() // 
}

function popupHandler(){
    // Custom Handler 생성
    var handler = new ObjC.Block({
        retType: 'void',
        argTypes: ['object'],
        implementation: function () {
            console.log("muffin");
        }
    });

    // +[UIAlertAction actionWithTitle:style:handler:] 후킹
    var className = "UIAlertAction";
    var funcName = "+ actionWithTitle:style:handler:";
    var hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            //args[4] = handler;
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
            console.warn("\n[+] Detected call to: " + className + " -> " + funcName);
            console.log("\n\x1b[31margs[2]:\x1b[0m \x1b[34m" + args[2] + ", \x1b[32m" + ObjC.Object(args[2]) + "\x1b[0m")
            console.log("\x1b[31margs[3]:\x1b[0m \x1b[34m" + args[3] + ", \x1b[32m" + ObjC.Object(args[3]) + "\x1b[0m")
            console.log("\x1b[31margs[4]:\x1b[0m \x1b[34m" + args[4] + ", \x1b[32m" + ObjC.Object(args[4]) + "\x1b[0m")    
        },
        onLeave: function(retval) {
            console.log("\n\x1b[31mretval:\x1b[0m \x1b[34m" + retval.toString() + ", \x1b[32m" + ObjC.Object(retval) + "\x1b[0m");  // after call
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n\t'));
            console.warn("[-] Exiting");
        }
    });
}

var BaseAddress = ''
var module_base = Module.findBaseAddress(BaseAddress);

if (ObjC.available) {
    try {
        //replace_func_void(0x3F3F20)
        show_original(0x5522F8)
        //show_original(0x5522E0)
    }
    catch (err) {
        console.log("[!] Exception2: " + err.message);
    }
}
else {
    console.log("Objective-C Runtime is not available!");
}