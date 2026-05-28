use anyhow::Context;
use aya::programs::TracePoint;
use tracing::info;

pub fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("program '{}' not found", program_name))?
        .try_into()
        .with_context(|| format!("program '{}' is not a tracepoint", program_name))?;

    program
        .load()
        .with_context(|| format!("failed to load tracepoint program '{program_name}'"))?;
    program.attach(category, event).with_context(|| {
        format!("failed to attach tracepoint program '{program_name}' to {category}:{event}")
    })?;
    info!(program = %program_name, category = %category, event = %event, "tracepoint attached");
    Ok(())
}
