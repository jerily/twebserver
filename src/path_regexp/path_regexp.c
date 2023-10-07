/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 *
 * This file is based on https://github.com/pillarjs/path-to-regexp
 * which is licensed under the MIT license.
 */


#include "path_regexp.h"

enum route_path_option_enum {
    TWS_ROUTE_PATH_OPTION_START = 1,
};

enum lex_token_type_enum {
    MODIFIER,
    ESCAPED_CHAR,
    OPEN,
    CLOSE,
    NAME,
    PATTERN,
    CHAR,
    END
};

int tws_PathExprLexer(Tcl_Interp *interp, const char *path_expr, int path_expr_len, Tcl_Obj *lexTokensListPtr) {
    const char *p = path_expr;
    const char *end = path_expr + path_expr_len;

    while (p < end) {
        char c = *p;
        if (c == '*' || c == '+' || c == '?') {
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(MODIFIER));
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, 1));
            p++;
            continue;
        }
        if (c == '\\') {
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(ESCAPED_CHAR));
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p + 1, 1));
            p += 2;
            continue;
        }
        if (c == '{') {
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(OPEN));
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, 1));
            p++;
            continue;
        }
        if (c == '}') {
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(CLOSE));
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, 1));
            p++;
            continue;
        }
        if (c == ':') {
            const char *q = p + 1;
            while (q < end && (CHARTYPE(alpha, *q) || CHARTYPE(digit, *q) || *q == '_')) {
                q++;
            }
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(NAME));
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, q - p));
            p = q;
            continue;
        }
        if (c == '(') {
            int count = 0;
            const char *q = p + 1;

            if (*q == '?') {
                SetResult("pattern cannot start with ?");
                return TCL_ERROR;
            }

            while (q < end) {
                if (*q == '\\') {
                    q += 2;
                    continue;
                }

                if (*q == ')') {
                    count--;
                    if (count == 0) {
                        q++;
                        break;
                    }
                    break;
                } else if (*q == '(') {
                    count++;
//                    if (*(q+1) == '?') {
//                         todo: Tcl_DecrRefCount
//                        SetResult("");
//                        return TCL_ERROR;
//                    }
                }

                q++;
            }

            if (count) {
                SetResult("unbalanced parentheses in pattern");
                return TCL_ERROR;
            }
            if (p == q + 1) {
                SetResult("empty group in pattern");
                return TCL_ERROR;
            }

            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(PATTERN));
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, q - p));
            p = q;
            continue;
        }

        Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(CHAR));
        Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, 1));
        p++;
    }

    Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewIntObj(END));
    Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p, 1));

    return TCL_OK;
}

Tcl_Obj *tws_TryConsume(Tcl_Obj **tokens, int *iPtr, int type) {
    if (Tcl_GetIntFromObj(NULL, tokens[*iPtr], NULL) == type) {
        Tcl_Obj *result = tokens[(*iPtr) + 1];
        (*iPtr) += 2;
        return result;
    }
    return NULL;
}

Tcl_Obj *tws_MustConsume(Tcl_Obj **tokens, int *iPtr, int type) {
    return tws_TryConsume(tokens, iPtr, type);
}

Tcl_Obj *tws_TryConsumeText() {
    // todo
}

int tws_PathExprToTokens(Tcl_Interp *interp, const char *path_expr, int path_expr_len, int flags, Tcl_Obj *tokensListPtr) {
    Tcl_Obj *lexTokensListPtr = Tcl_NewListObj(0, NULL);
    if (TCL_OK != tws_PathExprLexer(interp, path_expr, path_expr_len, lexTokensListPtr)) {
        SetResult("tws_PathExprLexer failed");
        return TCL_ERROR;
    }

    int lexTokensLen;
    Tcl_Obj **lexTokens;
    if (TCL_OK != Tcl_ListObjGetElements(interp, lexTokensListPtr, &lexTokensLen, &lexTokens)) {
        SetResult("failed to read list of lex tokens");
        return TCL_ERROR;
    }

    Tcl_Obj *defaultPatternPtr = Tcl_NewStringObj("[^\\/]+?", -1);
    int key = 0;
    Tcl_DString path;
    Tcl_DStringInit(&path);
    int i = 0;
    while (i < lexTokensLen) {
        Tcl_Obj *charPtr = tws_TryConsume(lexTokens, &i, CHAR);
        Tcl_Obj *namePtr = tws_TryConsume(lexTokens, &i, NAME);
        Tcl_Obj *patternPtr = tws_TryConsume(lexTokens, &i, PATTERN);

        if (namePtr != NULL || patternPtr != NULL) {
            Tcl_Obj *prefixPtr = charPtr ? charPtr : Tcl_NewStringObj("", -1);

//            if (prefixes.indexOf(prefix) === -1) {
//                path += prefix;
//                prefix = "";
//            }

            if (Tcl_DStringLength(&path)) {
                Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewStringObj(Tcl_DStringValue(&path), Tcl_DStringLength(&path)));
                Tcl_DStringTrunc(&path, 0);
            }

            Tcl_Obj *dictPtr = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("name", -1), namePtr ? namePtr : Tcl_NewIntObj(key++));
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("prefix", -1), prefixPtr);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("suffix", -1), Tcl_NewStringObj("", -1));
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("pattern", -1), patternPtr ? patternPtr : defaultPatternPtr);
            Tcl_Obj *modifierPtr = tws_TryConsume(lexTokens, &i, MODIFIER);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("modifier", -1), modifierPtr ? modifierPtr : Tcl_NewStringObj("", -1));
            Tcl_ListObjAppendElement(interp, tokensListPtr, dictPtr);
        }

        Tcl_Obj *valuePtr = charPtr ? charPtr : tws_TryConsume(lexTokens, &i, ESCAPED_CHAR);
        i += 2;
        if (valuePtr != NULL) {
            int value_len;
            const char *value = Tcl_GetStringFromObj(valuePtr, &value_len);
            Tcl_DStringAppend(&path, value, value_len);
            continue;
        }

        if (Tcl_DStringLength(&path)) {
            Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewStringObj(Tcl_DStringValue(&path), Tcl_DStringLength(&path)));
            Tcl_DStringTrunc(&path, 0);
        }

        Tcl_Obj *openPtr = tws_TryConsume(lexTokens, &i, OPEN);
        if (openPtr) {
            Tcl_Obj *openPrefixPtr = tws_TryConsumeText(lexTokens, &i);
            Tcl_Obj *openNamePtr = tws_TryConsume(lexTokens, &i, NAME);
            Tcl_Obj *openPatternPtr = tws_TryConsume(lexTokens, &i, PATTERN);
            Tcl_Obj *openSuffixPtr = tws_TryConsumeText(lexTokens, &i);

            if (!tws_MustConsume(lexTokens, &i, CLOSE)) {
                SetResult("missing closing brace");
                return TCL_ERROR;
            }

            Tcl_Obj *dictPtr = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("name", -1),
                           openNamePtr ? openNamePtr : (openPatternPtr ? Tcl_NewIntObj(key++) : Tcl_NewStringObj("", -1)));
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("prefix", -1), openPrefixPtr);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("suffix", -1), openSuffixPtr);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("pattern", -1),
                           openNamePtr && !openPatternPtr ? defaultPatternPtr : openPatternPtr);
            Tcl_Obj *modifierPtr = tws_TryConsume(lexTokens, &i, MODIFIER);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("modifier", -1), modifierPtr ? modifierPtr : Tcl_NewStringObj("", -1));
            Tcl_ListObjAppendElement(interp, tokensListPtr, dictPtr);

            continue;

        }

        if (!tws_MustConsume(lexTokens, &i, END)) {
            SetResult("unexpected character");
            return TCL_ERROR;
        }

    }
    Tcl_DStringFree(&path);
    return TCL_OK;
}

int tws_TokensToRegExp(Tcl_Interp *interp, Tcl_Obj *tokensListPtr, int flags, Tcl_DString *dsPtr) {
    return TCL_OK;
}

int tws_PathToRegExp(Tcl_Interp *interp, const char *path, int path_len, int flags, Tcl_RegExp *regexp) {

    Tcl_Obj *tokensListPtr = Tcl_NewListObj(0, NULL);
    if (TCL_OK != tws_PathExprToTokens(interp, path, path_len, flags, tokensListPtr)) {
        SetResult("tws_PathExprToTokens failed");
        return TCL_ERROR;
    }

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    if (TCL_OK != tws_TokensToRegExp(interp, tokensListPtr, flags, &ds)) {
        SetResult("tws_TokensToRegExp failed");
        return TCL_ERROR;
    }

    const char *pattern = Tcl_DStringValue(&ds);
    *regexp = Tcl_RegExpCompile(interp, pattern);
    Tcl_DStringFree(&ds);
    return TCL_OK;
}
