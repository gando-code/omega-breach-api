import { createClientFromRequest } from 'npm:@base44/sdk@0.8.40';
import { writeFile, getGitHub, repoUrl } from '../../shared/githubCorpus.ts';

// Publishes the BreachCorpus entity records into the GitHub repo as breaches/index.json.
export default async function(req: Request): Promise<Response> {
  try {
    const base44 = createClientFromRequest(req);
    const records = await base44.asServiceRole.entities.BreachCorpus.list('-created_date', 200);
    const index = records.map((r) => ({
      title: r.title,
      domain: (r.domain || '').toLowerCase(),
      breach_date: r.breach_date,
      data_classes: r.data_classes || [],
      accounts_affected: r.accounts_affected || 0,
      description: r.description || '',
      logo_url: r.logo_url || ''
    }));
    await writeFile(base44, 'breaches/index.json', index, 'seed breach corpus index');
    const { owner } = await getGitHub(base44);
    return Response.json({ published: index.length, repo: repoUrl(owner) });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}
