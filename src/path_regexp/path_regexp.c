/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 *
 * This file is based on https://github.com/pillarjs/path-to-regexp
 * which is licensed under the MIT license.
 */


#include "path_regexp.h"

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
            Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj(p + 1, q - p - 1));
            p = q;
            continue;
        }
        if (c == '(') {
            int count = 1;
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
    Tcl_ListObjAppendElement(interp, lexTokensListPtr, Tcl_NewStringObj("", -1));

    return TCL_OK;
}

Tcl_Obj *tws_TryConsume(Tcl_Obj **tokens, int *iPtr, int type) {
    int tokenType;
    if (TCL_OK != Tcl_GetIntFromObj(NULL, tokens[*iPtr], &tokenType)) {
        return NULL;
    }
    if (tokenType == type) {
        Tcl_Obj *result = tokens[(*iPtr) + 1];
        (*iPtr) += 2;
        return result;
    }
    return NULL;
}

Tcl_Obj *tws_MustConsume(Tcl_Obj **tokens, int *iPtr, int type) {
    return tws_TryConsume(tokens, iPtr, type);
}

Tcl_Obj *tws_TryConsumeText(Tcl_Obj **tokens, int *iPtr) {
    Tcl_Obj *resultPtr = Tcl_NewStringObj("", -1);
    Tcl_Obj *valuePtr = tws_TryConsume(tokens, iPtr, CHAR);
    if (valuePtr == NULL) {
        valuePtr = tws_TryConsume(tokens, iPtr, ESCAPED_CHAR);
    }
    while (valuePtr) {
        Tcl_AppendObjToObj(resultPtr, valuePtr);
        valuePtr = tws_TryConsume(tokens, iPtr, CHAR);
        if (valuePtr == NULL) {
            valuePtr = tws_TryConsume(tokens, iPtr, ESCAPED_CHAR);
        }
    }
    return resultPtr;
}

enum {
    STRING_TOKEN,
    DICT_TOKEN
};

int tws_PathExprToTokens(Tcl_Interp *interp, const char *path_expr, int path_expr_len, int flags, Tcl_Obj *tokensListPtr) {
    Tcl_Obj *lexTokensListPtr = Tcl_NewListObj(0, NULL);
    if (TCL_OK != tws_PathExprLexer(interp, path_expr, path_expr_len, lexTokensListPtr)) {
//        SetResult("PathExprLexer failed");
        return TCL_ERROR;
    }

    DBG2(printf("PathExprToTokens - lex tokens: %s\n", Tcl_GetString(lexTokensListPtr)));

    Tcl_Size lexTokensLen;
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

//        fprintf(stderr, "i: %d charPtr: %s, namePtr: %s, patternPtr: %s\n",
//                i,
//                charPtr ? Tcl_GetString(charPtr) : "NULL",
//                namePtr ? Tcl_GetString(namePtr) : "NULL",
//                patternPtr ? Tcl_GetString(patternPtr) : "NULL");

        if (namePtr != NULL || patternPtr != NULL) {

            int appended = 0;
            if (charPtr) {
                Tcl_Size prefix_len;
                const char *prefix = Tcl_GetStringFromObj(charPtr, &prefix_len);
                if (prefix[0] != '.' && prefix[0] != '/') {
                    Tcl_DStringAppend(&path, prefix, prefix_len);
                    appended = 1;
                }
            }
            Tcl_Obj *prefixPtr = !appended && charPtr ? charPtr : Tcl_NewStringObj("", -1);

            if (Tcl_DStringLength(&path)) {
                Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewIntObj(STRING_TOKEN));
                Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewStringObj(Tcl_DStringValue(&path), Tcl_DStringLength(&path)));
                Tcl_DStringSetLength(&path, 0);
            }

            Tcl_Obj *dictPtr = Tcl_NewDictObj();
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("name", -1), namePtr ? namePtr : Tcl_NewIntObj(key++));
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("prefix", -1), prefixPtr);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("suffix", -1), Tcl_NewStringObj("", -1));
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("pattern", -1), patternPtr ? patternPtr : defaultPatternPtr);
            Tcl_Obj *modifierPtr = tws_TryConsume(lexTokens, &i, MODIFIER);
            Tcl_DictObjPut(interp, dictPtr, Tcl_NewStringObj("modifier", -1), modifierPtr ? modifierPtr : Tcl_NewStringObj("", -1));
            Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewIntObj(DICT_TOKEN));
            Tcl_ListObjAppendElement(interp, tokensListPtr, dictPtr);
            continue;
        }

        Tcl_Obj *valuePtr = charPtr ? charPtr : tws_TryConsume(lexTokens, &i, ESCAPED_CHAR);
        if (valuePtr != NULL) {
            Tcl_Size value_len;
            const char *value = Tcl_GetStringFromObj(valuePtr, &value_len);
            Tcl_DStringAppend(&path, value, value_len);
            continue;
        }

        if (Tcl_DStringLength(&path)) {
            Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewIntObj(STRING_TOKEN));
            Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewStringObj(Tcl_DStringValue(&path), Tcl_DStringLength(&path)));
            Tcl_DStringSetLength(&path, 0);
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
            Tcl_ListObjAppendElement(interp, tokensListPtr, Tcl_NewIntObj(DICT_TOKEN));
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

void tws_DStringAppendEscaped(Tcl_DString *dsPtr, const char *str, int len) {
    // str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
    const char *p = str;
    const char *end = str + len;

    while (p < end) {
        char c = *p;
        if (c == '.' || c == '+' || c == '*' || c == '?' || c == '=' || c == '^' || c == '!' || c == ':' || c == '$' ||
            c == '{' || c == '}' || c == '(' || c == ')' || c == '[' || c == ']' || c == '|' || c == '/' || c == '\\') {
            Tcl_DStringAppend(dsPtr, "\\", 1);
        }
        Tcl_DStringAppend(dsPtr, p, 1);
        p++;
    }
}

int tws_TokensToRegExp(Tcl_Interp *interp, Tcl_Obj *tokensListPtr, int flags, Tcl_Obj *keysListPtr, Tcl_DString *dsPtr) {
    int strict = (flags & STRICT_MATCH);
    int start = (flags & START_MATCH);
    int end = (flags & END_MATCH);

    if (start) {
        Tcl_DStringAppend(dsPtr, "^", 1);
    }

    Tcl_Obj **tokens;
    Tcl_Size tokens_len;
    if (TCL_OK != Tcl_ListObjGetElements(interp, tokensListPtr, &tokens_len, &tokens)) {
        SetResult("failed to read list of tokens");
        return TCL_ERROR;
    }

    for (int i = 0; i < tokens_len; i+=2) {
        Tcl_Obj *typePtr = tokens[i];
        int type;
        if (TCL_OK != Tcl_GetIntFromObj(interp, typePtr, &type)) {
            SetResult("failed to read token type");
            return TCL_ERROR;
        }
        Tcl_Obj *tokenPtr = tokens[i + 1];

        if (type == STRING_TOKEN) {
            Tcl_Size token_len;
            const char *token = Tcl_GetStringFromObj(tokenPtr, &token_len);
            tws_DStringAppendEscaped(dsPtr, token, token_len);
        } else {
            Tcl_Obj *nameKeyPtr = Tcl_NewStringObj("name", -1);
            Tcl_IncrRefCount(nameKeyPtr);
            Tcl_Obj *namePtr;
            if (TCL_OK != Tcl_DictObjGet(interp, tokenPtr, nameKeyPtr, &namePtr)) {
                Tcl_DecrRefCount(nameKeyPtr);
                SetResult("failed to read token name");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(nameKeyPtr);

            Tcl_Obj *prefixKeyPtr = Tcl_NewStringObj("prefix", -1);
            Tcl_IncrRefCount(prefixKeyPtr);
            Tcl_Obj *prefixPtr;
            if (TCL_OK != Tcl_DictObjGet(interp, tokenPtr, prefixKeyPtr, &prefixPtr)) {
                Tcl_DecrRefCount(prefixKeyPtr);
                SetResult("failed to read token prefix");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(prefixKeyPtr);

            Tcl_Obj *suffixKeyPtr = Tcl_NewStringObj("suffix", -1);
            Tcl_IncrRefCount(suffixKeyPtr);
            Tcl_Obj *suffixPtr;
            if (TCL_OK != Tcl_DictObjGet(interp, tokenPtr, suffixKeyPtr, &suffixPtr)) {
                Tcl_DecrRefCount(suffixKeyPtr);
                SetResult("failed to read token suffix");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(suffixKeyPtr);

            Tcl_Obj *patternKeyPtr = Tcl_NewStringObj("pattern", -1);
            Tcl_IncrRefCount(patternKeyPtr);
            Tcl_Obj *patternPtr;
            if (TCL_OK != Tcl_DictObjGet(interp, tokenPtr, patternKeyPtr, &patternPtr)) {
                Tcl_DecrRefCount(patternKeyPtr);
                SetResult("failed to read token pattern");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(patternKeyPtr);

            Tcl_Obj *modifierKeyPtr = Tcl_NewStringObj("modifier", -1);
            Tcl_IncrRefCount(modifierKeyPtr);
            Tcl_Obj *modifierPtr;
            if (TCL_OK != Tcl_DictObjGet(interp, tokenPtr, modifierKeyPtr, &modifierPtr)) {
                Tcl_DecrRefCount(modifierKeyPtr);
                SetResult("failed to read token modifier");
                return TCL_ERROR;
            }
            Tcl_DecrRefCount(modifierKeyPtr);

            Tcl_Size pattern_len;
            const char *pattern = Tcl_GetStringFromObj(patternPtr, &pattern_len);
            Tcl_Size prefix_len;
            const char *prefix = Tcl_GetStringFromObj(prefixPtr, &prefix_len);
            Tcl_Size suffix_len;
            const char *suffix = Tcl_GetStringFromObj(suffixPtr, &suffix_len);
            Tcl_Size modifier_len;
            const char *modifier = Tcl_GetStringFromObj(modifierPtr, &modifier_len);

            if (pattern_len > 0) {
                Tcl_ListObjAppendElement(interp, keysListPtr, namePtr);

                if (prefix_len > 0 || suffix_len > 0) {
                    if (modifier[0] == '+' || modifier[0] == '*') {
//                        char mod = modifier[0] == '*' ? '?' : '';
//                        route += `(?:${prefix}((?:${token.pattern})(?:${suffix}${prefix}(?:${token.pattern}))*)${suffix})${mod}`;
                        Tcl_DStringAppend(dsPtr, "(?:", 3);
                        tws_DStringAppendEscaped(dsPtr, prefix, prefix_len);
                        Tcl_DStringAppend(dsPtr, "((?:", 4);
                        Tcl_DStringAppend(dsPtr, pattern, pattern_len);
                        Tcl_DStringAppend(dsPtr, ")(?:", 3);
                        tws_DStringAppendEscaped(dsPtr, suffix, suffix_len);
                        tws_DStringAppendEscaped(dsPtr, prefix, prefix_len);
                        Tcl_DStringAppend(dsPtr, "(?:", 3);
                        Tcl_DStringAppend(dsPtr, pattern, pattern_len);
                        Tcl_DStringAppend(dsPtr, "))*)", 4);
                        Tcl_DStringAppend(dsPtr, suffix, suffix_len);
                        Tcl_DStringAppend(dsPtr, ")", 1);
                        if (modifier[0] == '*') {
                            char mod = '?';
                            Tcl_DStringAppend(dsPtr, &mod, 1);
                        }
                    } else {
                        // route += `(?:${prefix}(${token.pattern})${suffix})${token.modifier}`;
                        Tcl_DStringAppend(dsPtr, "(?:", 3);
                        tws_DStringAppendEscaped(dsPtr, prefix, prefix_len);
                        Tcl_DStringAppend(dsPtr, "(", 1);
                        Tcl_DStringAppend(dsPtr, pattern, pattern_len);
                        Tcl_DStringAppend(dsPtr, ")", 1);
                        tws_DStringAppendEscaped(dsPtr, suffix, suffix_len);
                        Tcl_DStringAppend(dsPtr, ")", 1);
                        Tcl_DStringAppend(dsPtr, modifier, modifier_len);
                    }
                } else {
                    if (modifier[0] == '+' || modifier[0] == '*') {
                        // route += `((?:${token.pattern})${token.modifier})`;
                        Tcl_DStringAppend(dsPtr, "((?:", 4);
                        Tcl_DStringAppend(dsPtr, pattern, pattern_len);
                        Tcl_DStringAppend(dsPtr, ")", 1);
                        Tcl_DStringAppend(dsPtr, modifier, modifier_len);
                        Tcl_DStringAppend(dsPtr, ")", 1);
                    } else {
                        // route += `(${token.pattern})${token.modifier}`;
                        Tcl_DStringAppend(dsPtr, "(", 1);
                        Tcl_DStringAppend(dsPtr, pattern, pattern_len);
                        Tcl_DStringAppend(dsPtr, ")", 1);
                        Tcl_DStringAppend(dsPtr, modifier, modifier_len);
                    }
                }
            } else {
                // route += `(?:${prefix}${suffix})${token.modifier}`;
                Tcl_DStringAppend(dsPtr, "(?:", 3);
                tws_DStringAppendEscaped(dsPtr, prefix, prefix_len);
                Tcl_DStringAppend(dsPtr, suffix, suffix_len);
                tws_DStringAppendEscaped(dsPtr, ")", 1);
                Tcl_DStringAppend(dsPtr, modifier, modifier_len);

            }
        }
    }

    char delimiterRe[3] = {'\\', '/', 0};
    if (end) {
        if (!strict) {
            // route += `${delimiterRe}?`;
            Tcl_DStringAppend(dsPtr, delimiterRe, 2);
            Tcl_DStringAppend(dsPtr, "?", 1);
        }
        Tcl_DStringAppend(dsPtr, "$", 1);
    } else {

        if (!strict) {
            // route += `(?:${delimiterRe}(?=${endsWithRe}))?`;
            Tcl_DStringAppend(dsPtr, delimiterRe, 2);
            Tcl_DStringAppend(dsPtr, "?", 1);
        }

        Tcl_Obj *endTokenTypePtr = tokens[tokens_len - 2];
        int endTokenType;
        if (TCL_OK != Tcl_GetIntFromObj(interp, endTokenTypePtr, &endTokenType)) {
            SetResult("failed to read end token type");
            return TCL_ERROR;
        }
        Tcl_Obj *endTokenPtr = tokens[tokens_len - 1];
        Tcl_Size endTokenLen;
        const char *endToken = Tcl_GetStringFromObj(endTokenPtr, &endTokenLen);

        int isEndDelimited = endTokenType == STRING_TOKEN ?
                endToken[endTokenLen - 1] == '/'
                : endTokenLen == 0;

        if (!isEndDelimited) {
            // route += `(?=${delimiterRe}|${endsWithRe})`;
            Tcl_DStringAppend(dsPtr, "(?=", 3);
            Tcl_DStringAppend(dsPtr, delimiterRe, 2);
            Tcl_DStringAppend(dsPtr, ")", 1);
        }
    }
    return TCL_OK;
}

int tws_PathToRegExp(Tcl_Interp *interp, const char *path, Tcl_Size path_len, int flags, Tcl_Obj **keys, char **pattern) {

    Tcl_Obj *tokensListPtr = Tcl_NewListObj(0, NULL);
    Tcl_IncrRefCount(tokensListPtr);
    if (TCL_OK != tws_PathExprToTokens(interp, path, path_len, flags, tokensListPtr)) {
        Tcl_DecrRefCount(tokensListPtr);
//        SetResult("tws_PathExprToTokens failed");
        return TCL_ERROR;
    }

    DBG2(printf("PathToRegExp - tokens: %s\n", Tcl_GetString(tokensListPtr)));

    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    Tcl_Obj *keysListPtr = Tcl_NewListObj(0, NULL);
    Tcl_IncrRefCount(keysListPtr);
    if (TCL_OK != tws_TokensToRegExp(interp, tokensListPtr, flags, keysListPtr, &ds)) {
        Tcl_DecrRefCount(tokensListPtr);
        Tcl_DecrRefCount(keysListPtr);
        SetResult("tws_TokensToRegExp failed");
        return TCL_ERROR;
    }

    *pattern = ckalloc(Tcl_DStringLength(&ds) + 1);
    memcpy(*pattern, Tcl_DStringValue(&ds), Tcl_DStringLength(&ds));
    (*pattern)[Tcl_DStringLength(&ds)] = '\0';
    DBG2(printf("PathToRegExp - pattern: %s\n", *pattern));
    *keys = keysListPtr;
    Tcl_DecrRefCount(tokensListPtr);
    Tcl_DStringFree(&ds);
    return TCL_OK;
}
