package com.mobileagent.mobile_agent

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

/**
 * TermuxBridge exposes the host-device's Termux shell to Flutter.
 *
 * Pre-conditions for it to work on the user's device:
 *  1. Termux app installed (F-Droid or GitHub release).
 *  2. ~/.termux/termux.properties contains `allow-external-apps=true`.
 *  3. This app has been granted `com.termux.permission.RUN_COMMAND`.
 *
 * MethodChannel  : io.mobileagent/termux
 *   - isAvailable()           : Bool
 *   - exec(command, args?)    : { stdout, stderr, exit }
 *
 * EventChannel   : io.mobileagent/termux/events
 *   - emits { stdout, stderr, exit } in streaming mode (background = false).
 */
object TermuxBridge {
    private const val METHOD_CHANNEL = "io.mobileagent/termux"
    private const val EVENT_CHANNEL = "io.mobileagent/termux/events"
    private const val TERMUX_PACKAGE = "com.termux"
    private const val RUN_COMMAND_SERVICE = "com.termux.app.RunCommandService"
    private const val RUN_COMMAND_ACTION = "com.termux.RUN_COMMAND"
    private const val BASH_PATH = "/data/data/com.termux/files/usr/bin/bash"
    private const val WORKDIR_DEFAULT = "/data/data/com.termux/files/home"

    private var eventSink: EventChannel.EventSink? = null

    fun register(context: Context, engine: FlutterEngine) {
        val mc = MethodChannel(engine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
        mc.setMethodCallHandler { call, result ->
            when (call.method) {
                "isAvailable" -> result.success(isTermuxInstalled(context))
                "exec" -> {
                    val command = call.argument<String>("command") ?: ""
                    if (command.isBlank()) {
                        result.error("INVALID_ARGS", "command required", null)
                        return@setMethodCallHandler
                    }
                    runOnce(context, command, result)
                }
                else -> result.notImplemented()
            }
        }

        EventChannel(engine.dartExecutor.binaryMessenger, EVENT_CHANNEL)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
                    eventSink = events
                }
                override fun onCancel(arguments: Any?) {
                    eventSink = null
                }
            })
    }

    private fun isTermuxInstalled(ctx: Context): Boolean {
        return try {
            ctx.packageManager.getPackageInfo(TERMUX_PACKAGE, 0)
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun runOnce(ctx: Context, command: String, result: MethodChannel.Result) {
        val intent = Intent(RUN_COMMAND_ACTION).apply {
            setClassName(TERMUX_PACKAGE, RUN_COMMAND_SERVICE)
            putExtra("com.termux.RUN_COMMAND_PATH", BASH_PATH)
            putExtra("com.termux.RUN_COMMAND_ARGUMENTS", arrayOf("-c", command))
            putExtra("com.termux.RUN_COMMAND_WORKDIR", WORKDIR_DEFAULT)
            putExtra("com.termux.RUN_COMMAND_BACKGROUND", true)
            putExtra("com.termux.RUN_COMMAND_SESSION_ACTION", "0")
        }

        val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
            override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                val stdout = resultData?.getString("stdout") ?: ""
                val stderr = resultData?.getString("stderr") ?: ""
                val exit = resultData?.getInt("exitCode") ?: -1
                result.success(mapOf(
                    "stdout" to stdout,
                    "stderr" to stderr,
                    "exit" to exit,
                ))
                eventSink?.success(mapOf(
                    "stdout" to stdout,
                    "stderr" to stderr,
                    "exit" to exit,
                ))
            }
        }
        intent.putExtra("com.termux.RUN_COMMAND_RESULT_RECEIVER", receiver)

        try {
            ctx.startService(intent)
        } catch (e: Throwable) {
            result.error("TERMUX_FAIL", e.message, null)
        }
    }
}
