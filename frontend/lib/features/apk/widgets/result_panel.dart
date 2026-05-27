import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class ResultPanel extends StatelessWidget {
  final String? content;
  final bool isRunning;
  final bool isError;
  final String emptyHint;

  const ResultPanel({
    super.key,
    required this.content,
    this.isRunning = false,
    this.isError = false,
    this.emptyHint = 'Output will appear here',
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    if (isRunning) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
          borderRadius: BorderRadius.circular(8),
          border: Border(left: BorderSide(color: theme.colorScheme.primary, width: 3)),
        ),
        child: const Row(
          children: [
            SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)),
            SizedBox(width: 12),
            Text('Running...'),
          ],
        ),
      );
    }

    if (content == null || content!.isEmpty) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(24),
        alignment: Alignment.center,
        child: Text(emptyHint, style: theme.textTheme.bodySmall?.copyWith(color: Colors.grey)),
      );
    }

    final borderColor = isError ? theme.colorScheme.error : Colors.green;
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
        borderRadius: BorderRadius.circular(8),
        border: Border(left: BorderSide(color: borderColor, width: 3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.only(left: 12, right: 4, top: 4),
            child: Row(
              children: [
                Icon(isError ? Icons.error_outline : Icons.check_circle_outline,
                    size: 14, color: borderColor),
                const SizedBox(width: 6),
                Text(isError ? 'Error' : 'Done',
                    style: TextStyle(fontSize: 11, color: borderColor, fontWeight: FontWeight.w600)),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.copy, size: 14),
                  tooltip: 'Copy to clipboard',
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: content!));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Copied'), duration: Duration(seconds: 1)),
                    );
                  },
                  visualDensity: VisualDensity.compact,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                ),
              ],
            ),
          ),
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
              child: SelectableText(
                content!,
                style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class MenuButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool selected;
  final bool running;
  final bool hasResult;
  final bool primary;
  final VoidCallback? onPressed;

  const MenuButton({
    super.key,
    required this.icon,
    required this.label,
    required this.selected,
    required this.onPressed,
    this.running = false,
    this.hasResult = false,
    this.primary = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final disabled = onPressed == null;
    final accent = theme.colorScheme.primary;
    final textColor = disabled
        ? theme.disabledColor
        : (selected || primary ? accent : theme.colorScheme.onSurface);
    final bg = selected
        ? accent.withValues(alpha: 0.14)
        : (primary ? accent.withValues(alpha: 0.06) : null);
    final borderColor = selected
        ? accent.withValues(alpha: 0.6)
        : (primary
            ? accent.withValues(alpha: 0.4)
            : theme.dividerColor);

    return InkWell(
      onTap: onPressed,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: borderColor),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (running)
              const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            else
              Icon(icon, size: 16, color: textColor),
            const SizedBox(width: 6),
            Text(
              label,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: textColor,
                fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
              ),
            ),
            if (hasResult && !running) ...[
              const SizedBox(width: 6),
              const Icon(Icons.check_circle, size: 12, color: Colors.green),
            ],
          ],
        ),
      ),
    );
  }
}

class CaptureChip extends StatelessWidget {
  final String label;
  final IconData icon;
  final Color? color;

  const CaptureChip({super.key, required this.label, required this.icon, this.color});

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.onSurface;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: c.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: c),
          const SizedBox(width: 4),
          Text(label, style: TextStyle(fontSize: 10, color: c, fontWeight: FontWeight.w500)),
        ],
      ),
    );
  }
}
