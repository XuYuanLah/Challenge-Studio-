# Peer Feedback and Our Response

## Feedback received and overall response

We had a review of our Consumer IoT Anomaly Detection project by Jordan and Martin. They understood the use of real hardware and network traffic and Martin added that the behavioural baselines and transparent detection rules, network segmentation and repeatable testing. Thank you for this feedback as these were some of the aspects that lie at the heart of the workflow we're working on.

The need for clear communication was the most common criticism: it was unclear to many watching that were not terribly familiar with the technical details, and there were indications that this relationship wasn't as clear as it could have been. We share the foresight to those sentiments, legitimate concerns. Revisions will emphasize provision of clarity in presentation and evidence of the process of tracing evidence.

## Explainations of the technical aspects were confusing

Understanding of the data was challenging if you weren't familiar with that field, Jordan said. The diagrams are also suggested to be simplified, as well as the explanations, by Martin. We agree. It would seem we went too far into the technical aspects before we set out the problem and the significance of each of the results.

We'll be covering workflow in simple terms – see the typical traffic that goes through the device, set rules to detect the anomalies, and segment those that shouldn't be allowed to connect. On the first mention of terms like anomaly or baseline, we will describe them, simplify the topology diagram and provide a description of one example of normal traffic, and one suspicious traffic example, before presenting these outputs in detail. Redaction may not be of detailed logs that are maintained as evidence.

## The presentation format made the project harder to follow

Presenting using something like PowerPoint or Google Slides, Jordan said. We agree there is stakeholders' concern regarding structure, readability. Even if the software selected was the perfect solution, we must also make improvements on the order of explanation and the volume of the information that is displayed at a time.

We will be using a slide deck for the final presentation, and want to present them in a logical order - problem, proposed workflow, implementation, selected results, limitations and conclusions. Each of the slides in results will tell you what has been tested, and the significance of the result. The previous will be illustrated with screenshots and short demonstrations.

## The connection between evidence and results was unclear

Having greater clarity of links between evidence and research outcomes was suggested by Martin. We agree, but it's particularly important in our project, as there are a few different questions that can be answered by packet captures, detection outputs and segmentation tests. Explaining what each supports may be necessary if we are going to include these without any explanation, the audience may not know which are supporting which conclusion.

We will try and create a mapping of each evaluation scenario to its eventual outcome, observed outcome, rule and/or configuration relevant to the scenario, and evidence reference. Anyone who knows about anomaly detection will recognize that we will be differentiating anomaly detection and evidence of anomaly detection blocking an connection. If evidence is limited, we will indicate this as unverified or partially met but not surmise that it is met. For any detections and false positive claims we will provide an explanation for what was observed.

## Completion claims and remain evaluation

Jordan believed the problem he'd stated had been solved, though Martin was more optimistic, saying there still were tasks to do to get this going, including further testing and dashboard development. We welcome and agree with your favorable evaluation, but would limit any statement that the problem is solved to a certain extent. Given the variety of devices and scenarios, no tests can be done on them that can reliably detect the compromise of all types.

The success criteria will be checked on the evidence that is given for the final portfolio and all areas which are met/partially met/not yet verified will be discussed. The practical relevance brought by real hardware contributes to limit the conclusions; however, the number of devices, the monitoring time, and the number of scenarios tested remain low. Time and resources will be allocated to improving longer observations, and broad testing and improvements to the dashboard. In case of not yet achievable items a proposed test method, a discussion of feasibility or future-work plan can be done.

## Reflection and supporting feedback

This review reveals that technical improvement is more difficult to evaluate when for the audience it is not possible to follow the explanation or to follow a claim to its evidence. We focus on improving the understanding and verifiability of the existing workflow, results and limitations. Feedback doesn't necessarily mean we need to redesign everything, or that we can claim to be able to protect against all IoT attacks.