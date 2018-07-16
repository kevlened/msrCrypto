'================================================================
' Prepares script for release:
'
' - Removes the extra copyright headers from each bundled file
'   and just leaves the first one at the top
' - Removes the jscop/jshint exceptions and annotations
' - Removes the 'source' lines from the bundling process
' - Gets rid of the resulting extra line breaks from all the 
'   replacements
'
' Usage:
'   release.vbs inputfile [outputfile]
'
'   - inputfile:  msrcrypto.js file built by VS
'   - outputfile: Saves the modified file to a new file
'                 If you ommit the outputfile, the input
'                 file will be overwritten with the changes
'================================================================

Set args = Wscript.Arguments

Set objShell = CreateObject("Wscript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set oRegExp = New RegExp

inputFile = args(0)

if args.length < 2 then
    outputFile = inputFile
else 
    outputFile = args(1)
end if

Set objFile = objFSO.OpenTextFile(inputFile)

text = objFile.ReadAll

objFile.Close()

fileName = objFSO.GetFileName(inputFile)

oRegExp.Global = true
oRegExp.IgnoreCase = true

'Remove Copyright headers
 oRegExp.Pattern = "(\s*//\*+.+\r?\n)(\s*//[^\*]+\r?\n)*(\s*//\*+.+\r?\n)"
 copyright = oRegExp.Execute(text)(0)
 text = oRegExp.Replace(text,vbNewLine)

'Restore a single copyright at the top of the file
 text = copyright & text

'Remove jscop regions
 'oRegExp.Pattern = "(/// #region JSCop/JsHint\r?\n)(.*\r?\n)+?(/// #endregion JSCop/JsHint\r?\n)"
 oRegExp.Pattern = "(/// #region JSCop/JsHint[\S\s]*?#endregion JSCop/JsHint\r?\n)"
 text = oRegExp.Replace(text,vbNewLine)

'Remove debug sections
 oRegExp.Pattern = "/{2,3}#debug[\s\S]*?/{2,3}#enddebug"
 text = oRegExp.Replace(text,vbNewLine)

'Remove jscop exceptions
 oRegExp.Pattern = ".*///\s*<(disable|enable)>.*\r?\n"
 text = oRegExp.Replace(text,"")

'Remove bundle 'source' statements
 oRegExp.Pattern = "///#source.*\r?\n"
 text = oRegExp.Replace(text,vbNewLine)

'JsCop parameter annotations (i.e. /*@type(String)*/)
 oRegExp.Pattern = "\s*/\*\s*@\w+(\(\s*\w+\s*\))?\s*\*/\s*"
 text = oRegExp.Replace(text," ")

'jshint exceptions
 oRegExp.Pattern = "/\*\s*jshint.*\n"
 text = oRegExp.Replace(text,vbNewLine)

'Normalize line breaks
 oRegExp.Pattern = "\r"
 text = oRegExp.Replace(text,"")
 oRegExp.Pattern = "\n"
 text = oRegExp.Replace(text,vbCrLf)

'Remove multi-line breaks
 oRegExp.Pattern = "\r\n\s*\r\n\s*\r\n"
 text = oRegExp.Replace(text,vbNewLine & vbNewLine)

Set oReleaseFile = objFSO.CreateTextFile(outputFile, true)
oReleaseFile.WriteLine(text) 
oReleaseFile.Close()