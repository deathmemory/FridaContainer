"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: FCAnd.js
 * @time: 2020/9/3 3:40 PM
 * @desc:
 */
const Anti_1 = require("./android/Anti");
const andOpts_1 = require("./android/andOpts");
const jnimgr_1 = require("./android/jnimgr");
var FCAnd;
(function (FCAnd) {
    FCAnd.anti = Anti_1.Anti;
    FCAnd.andOpts = andOpts_1.AndOpts;
    FCAnd.jni = jnimgr_1.Jni;
})(FCAnd = exports.FCAnd || (exports.FCAnd = {}));
