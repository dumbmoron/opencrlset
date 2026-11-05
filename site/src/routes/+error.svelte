<script lang="ts">
  import { page } from "$app/state";
</script>

<p class="error">{page.error?.message ?? "Unknown error"}</p>
