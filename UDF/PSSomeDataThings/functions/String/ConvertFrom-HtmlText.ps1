function ConvertFrom-HtmlText {
    <#
    .SYNOPSIS
        Converts an HTML fragment to plain text.

    .DESCRIPTION
        Decodes HTML entities, strips remaining tags, and collapses
        whitespace runs to a single space. Designed for cell-content
        extraction from parsed HTML (table cells, attribute values
        with rich markup, GPMC saved reports, ...): you give it the
        inner HTML, you get the displayed text.

        Entity decoding uses [System.Net.WebUtility]::HtmlDecode, so
        every standard named entity (and numeric / hex character
        references) is handled - no maintained list of replacements.
        By default the decoder runs TWICE, so double-encoded inputs
        (e.g. "&amp;#39;" that GPMC sometimes emits) collapse to
        their final character in one call. Pass -Iterations 1 for a
        single pass when you know your input is single-encoded and
        want to preserve a literal "&amp;".

        Tag stripping is regex-based and removes any "<...>" run,
        but <br> / <br/> tags are first replaced with a space so
        adjacent lines don't run together. Whitespace is collapsed
        last and the result is trimmed.

    .PARAMETER Html
        Raw HTML fragment. Accepts pipeline input. Null and empty
        inputs return an empty string.

    .PARAMETER Iterations
        How many HtmlDecode passes to run. Default 2 covers the
        common double-encoded case. 1 is enough for well-formed
        HTML; higher values are safe (idempotent past full decode).

    .OUTPUTS
        System.String. The displayed text with entities resolved,
        tags removed, and internal whitespace collapsed to single
        spaces. Always returns a string (never $null).

    .EXAMPLE
        ConvertFrom-HtmlText '&lt;b&gt;Hello&lt;/b&gt;&nbsp;world'
        # -> 'Hello world'

    .EXAMPLE
        ConvertFrom-HtmlText '&amp;#39;quoted&amp;#39;'
        # -> "'quoted'" (two decode passes resolve the double encoding)

    .EXAMPLE
        ConvertFrom-HtmlText '<td>row<br/>break</td>'
        # -> 'row break' (br -> space before tag strip)

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-28) - Initial version. Extracted from
                             Read-ADGroupPolicyReportHtml so the
                             entity/strip/normalise pipeline is
                             reusable for any HTML-as-text parsing
                             (saved reports, scraped pages, ...).
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Html,

        [ValidateRange(1, 10)]
        [int]$Iterations = 2
    )

    Process {
        if ([string]::IsNullOrEmpty($Html)) { return '' }

        $sOut = $Html
        for ($i = 0; $i -lt $Iterations; $i++) {
            $sOut = [System.Net.WebUtility]::HtmlDecode($sOut)
        }

        # <br> -> space so line-broken cell text doesn't fuse.
        $sOut = $sOut -replace '<br\s*/?\s*>', ' '
        # Strip any remaining tag.
        $sOut = $sOut -replace '<[^>]+>', ''
        # Collapse internal whitespace runs (including any \n / \t
        # that survived) to a single space and trim ends.
        $sOut = $sOut -replace '\s+', ' '
        return $sOut.Trim()
    }
}
