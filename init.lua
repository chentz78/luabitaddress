--print(package.path)
package.path = package.path..";./modules/?.lua;./?.luac;./modules/?.luac"
package.cpath = package.cpath..";./modules/?.so"
